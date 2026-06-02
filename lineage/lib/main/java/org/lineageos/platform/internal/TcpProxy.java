/**
 * Copyright (C) 2022 Hallo Welt Systeme UG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.lineageos.platform.internal;

import android.content.pm.PackageManager;
import android.util.Slog;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Predicate;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import libcore.io.IoUtils;

/**
 * Raw TCP proxy on port 80 (HTTP) or 443 (HTTPS).
 *
 * Peeks the first bytes of each incoming connection to extract the hostname
 * (SNI for HTTPS, Host header for HTTP), notifies the BlockListener, then
 * serves the block page — plain HTTP on port 80, MITM TLS on port 443.
 */
class TcpProxy {

    interface BlockListener {
        void onBlocked(String domain, int uid, String packageName, String appName);
    }

    private static final String TAG = "TcpProxy";

    // Passes the already-parsed SNI to SNIKeyManager during the MITM TLS handshake.
    // Conscrypt's server-side getRequestedServerNames() is unreliable in the loopback
    // bridge setup, so we carry the SNI on the calling thread via ThreadLocal instead.
    static final ThreadLocal<String> sBridgeSni = new ThreadLocal<>();

    private final int mPort;
    private final SSLContext mSSLContext; // null for HTTP (port 80)
    private final Supplier<String> mBlockPageSupplier;
    private final BlockListener mListener;
    private final PackageManager mPackageManager;
    private final Predicate<String> mIsAllowed;

    private ServerSocket mServerSocket;
    private Thread mAcceptThread;
    private volatile boolean mRunning;
    private final ExecutorService mPool = Executors.newCachedThreadPool();

    TcpProxy(int port, SSLContext sslContext, Supplier<String> blockPageSupplier,
            BlockListener listener, PackageManager packageManager, Predicate<String> isAllowed) {
        mPort = port;
        mSSLContext = sslContext;
        mBlockPageSupplier = blockPageSupplier;
        mListener = listener;
        mPackageManager = packageManager;
        mIsAllowed = isAllowed;
    }

    void start() throws IOException {
        mServerSocket = new ServerSocket(mPort);
        mRunning = true;
        mAcceptThread = new Thread(this::acceptLoop, "TcpProxy-" + mPort + "-accept");
        mAcceptThread.setDaemon(true);
        mAcceptThread.start();
        Slog.i(TAG, "started on port " + mPort);
    }

    void stop() {
        mRunning = false;
        IoUtils.closeQuietly(mServerSocket);
        mPool.shutdown();
        Slog.i(TAG, "stopped port " + mPort);
    }

    private void acceptLoop() {
        while (mRunning) {
            try {
                Socket client = mServerSocket.accept();
                mPool.execute(() -> handle(client));
            } catch (IOException e) {
                if (mRunning) Slog.e(TAG, "accept error on port " + mPort, e);
            }
        }
    }

    private void handle(Socket client) {
        try {
            client.setSoTimeout(10_000);
            byte[] peek = new byte[4096];
            int n = client.getInputStream().read(peek);
            if (n <= 0) {
                IoUtils.closeQuietly(client);
                return;
            }

            String domain = (mSSLContext != null)
                ? parseSniFromClientHello(peek, n)
                : parseHostFromHttpRequest(peek, n);

            int uid = getUidFromSocket(client);
            String pkg = getPackageForUid(mPackageManager, uid);
            String appName = getAppNameForUid(mPackageManager, uid);
            Slog.i(TAG, "App " + appName + " (" + pkg + ") on port " + mPort
                + " trying to access " + domain);

            // If the domain was recently allowed (e.g. after tapping "Allow" in a notification,
            // or the browser DNS cache still points to us after dnsmasq was updated), pass through
            // transparently to the real server instead of serving the block page.
            if (domain != null && mIsAllowed.test(domain)) {
                passThrough(client, peek, n, domain);
                return;
            }

            mListener.onBlocked(domain != null ? domain : "unknown", uid, pkg, appName);

            if (mSSLContext != null) {
                sBridgeSni.set(domain);
                try {
                    mitmBlock(client, peek, n);
                } finally {
                    sBridgeSni.remove();
                }
            } else {
                serveBlockPage(client);
            }
        } catch (Exception e) {
            Slog.e(TAG, "handle error on port " + mPort, e);
            IoUtils.closeQuietly(client);
        }
    }

    // ── HTTPS MITM block (port 443) ────────────────────────────────────────

    private void mitmBlock(Socket client, byte[] peeked, int n) {
        try {
            // Conscrypt doesn't support createSocket(Socket, InputStream, boolean).
            // Use a loopback bridge so SSLSocket can use createSocket(Socket, String, int, boolean).
            ServerSocket bridge = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            bridge.setSoTimeout(5000);
            Socket connector = new Socket(InetAddress.getLoopbackAddress(), bridge.getLocalPort());
            Socket bridgeAccepted = bridge.accept();
            bridge.close();

            // Replay peeked ClientHello bytes, then relay the rest of the client stream.
            connector.getOutputStream().write(peeked, 0, n);
            mPool.execute(() -> {
                try { pipe(client.getInputStream(), connector.getOutputStream()); }
                catch (Exception ignored) {}
                finally { IoUtils.closeQuietly(connector); }
            });

            // Relay TLS-encrypted responses back to the browser.
            mPool.execute(() -> {
                try { pipe(connector.getInputStream(), client.getOutputStream()); }
                catch (Exception ignored) {}
                finally { IoUtils.closeQuietly(client); }
            });

            SSLSocket ssl = (SSLSocket) mSSLContext.getSocketFactory()
                .createSocket(bridgeAccepted, "blocked.local", 443, true);
            ssl.setUseClientMode(false);
            ssl.setSoTimeout(10_000);
            ssl.startHandshake();

            // Drain HTTP request headers.
            InputStream in = ssl.getInputStream();
            byte[] req = new byte[8192];
            int reqLen = 0;
            while (reqLen < req.length) {
                int b = in.read();
                if (b < 0) break;
                req[reqLen++] = (byte) b;
                if (reqLen >= 4
                        && req[reqLen - 4] == '\r' && req[reqLen - 3] == '\n'
                        && req[reqLen - 2] == '\r' && req[reqLen - 1] == '\n') break;
            }

            byte[] body = mBlockPageSupplier.get().getBytes(StandardCharsets.UTF_8);
            OutputStream out = ssl.getOutputStream();
            out.write(("HTTP/1.1 200 OK\r\n"
                + "Content-Type: text/html; charset=utf-8\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "Connection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            out.write(body);
            out.flush();
            ssl.close();
        } catch (Exception e) {
            Slog.e(TAG, "mitmBlock error", e);
            IoUtils.closeQuietly(client);
        }
    }

    // ── HTTP block (port 80) ───────────────────────────────────────────────

    private void serveBlockPage(Socket client) {
        try {
            byte[] body = mBlockPageSupplier.get().getBytes(StandardCharsets.UTF_8);
            OutputStream out = client.getOutputStream();
            out.write(("HTTP/1.1 200 OK\r\n"
                + "Content-Type: text/html; charset=utf-8\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "Connection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            out.write(body);
            out.flush();
        } catch (Exception e) {
            Slog.e(TAG, "serveBlockPage error", e);
        } finally {
            IoUtils.closeQuietly(client);
        }
    }

    // ── SNI / Host parsing ─────────────────────────────────────────────────

    /**
     * Extracts the SNI hostname from raw TLS ClientHello bytes.
     * Returns null if not a ClientHello or the SNI extension is absent.
     *
     * TLS record: [0]=0x16 [1-2]=version [3-4]=recordLen
     * Handshake:  [5]=0x01 [6-8]=bodyLen [9-10]=clientVersion
     *             [11-42]=random [43]=sidLen …
     * Extensions: type(2)+len(2)+data; SNI type=0x0000
     */
    static String parseSniFromClientHello(byte[] buf, int len) {
        try {
            if (len < 43) return null;
            if ((buf[0] & 0xFF) != 0x16) return null;
            if ((buf[5] & 0xFF) != 0x01) return null;

            int pos = 43;
            if (pos >= len) return null;

            int sidLen = buf[pos++] & 0xFF;
            pos += sidLen;
            if (pos + 2 > len) return null;

            int csLen = ((buf[pos] & 0xFF) << 8) | (buf[pos + 1] & 0xFF);
            pos += 2 + csLen;
            if (pos >= len) return null;

            int cmLen = buf[pos++] & 0xFF;
            pos += cmLen;
            if (pos + 2 > len) return null;

            int extTotal = ((buf[pos] & 0xFF) << 8) | (buf[pos + 1] & 0xFF);
            pos += 2;
            int extEnd = pos + extTotal;

            while (pos + 4 <= extEnd && pos + 4 <= len) {
                int extType = ((buf[pos] & 0xFF) << 8) | (buf[pos + 1] & 0xFF);
                int extLen = ((buf[pos + 2] & 0xFF) << 8) | (buf[pos + 3] & 0xFF);
                pos += 4;
                if (extType == 0x0000) {
                    pos += 2;
                    if (pos >= len || buf[pos] != 0x00) return null;
                    pos++;
                    if (pos + 2 > len) return null;
                    int nameLen = ((buf[pos] & 0xFF) << 8) | (buf[pos + 1] & 0xFF);
                    pos += 2;
                    if (pos + nameLen > len) return null;
                    return new String(buf, pos, nameLen, StandardCharsets.US_ASCII);
                }
                pos += extLen;
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Extracts the Host header value from raw HTTP request bytes.
     * Returns null if the Host header is absent.
     */
    static String parseHostFromHttpRequest(byte[] buf, int len) {
        try {
            String req = new String(buf, 0, len, StandardCharsets.ISO_8859_1);
            for (String line : req.split("\r\n")) {
                if (line.isEmpty()) break;
                if (line.toLowerCase(Locale.ROOT).startsWith("host:")) {
                    String host = line.substring(5).trim();
                    int colon = host.indexOf(':');
                    return colon >= 0 ? host.substring(0, colon) : host;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ── UID / app name lookup ──────────────────────────────────────────────

    /**
     * Reads /proc/net/tcp (IPv4) or /proc/net/tcp6 (IPv6) to find the UID of
     * the app whose local socket endpoint matches the client's source address/port.
     */
    static int getUidFromSocket(Socket socket) {
        try {
            InetAddress addr = socket.getInetAddress();
            int port = socket.getPort();
            byte[] b = addr.getAddress();

            String portHex = String.format("%04X", port);
            String addrHex;
            String procFile;

            if (b.length == 4) {
                addrHex = String.format("%02X%02X%02X%02X",
                    b[3] & 0xFF, b[2] & 0xFF, b[1] & 0xFF, b[0] & 0xFF);
                procFile = "/proc/net/tcp";
            } else {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 4; i++) {
                    int g = i * 4;
                    sb.append(String.format("%02X%02X%02X%02X",
                        b[g+3] & 0xFF, b[g+2] & 0xFF, b[g+1] & 0xFF, b[g] & 0xFF));
                }
                addrHex = sb.toString();
                procFile = "/proc/net/tcp6";
            }

            String localTarget = addrHex + ":" + portHex;
            try (BufferedReader br = new BufferedReader(new FileReader(procFile))) {
                String header = br.readLine();
                if (header == null) return -1;
                int uidIdx = parseUidDataIndex(header);
                String line;
                while ((line = br.readLine()) != null) {
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length > uidIdx
                            && parts[1].equalsIgnoreCase(localTarget)
                            && parts[3].equals("01")) {
                        return Integer.parseInt(parts[uidIdx]);
                    }
                }
            }
        } catch (Exception ignored) {}
        return -1;
    }

    /**
     * Maps the "uid" word in the /proc/net/tcp header to its data-row field index,
     * accounting for merged fields (tx_queue+rx_queue, tr+tm->when).
     */
    private static int parseUidDataIndex(String header) {
        String[] words = header.trim().split("\\s+");
        int merged = 0;
        boolean prevWasTxQueue = false;
        boolean prevWasTr = false;
        for (int i = 0; i < words.length; i++) {
            String w = words[i].toLowerCase(Locale.ROOT);
            if ("uid".equals(w)) return i - merged;
            if ("rx_queue".equals(w) && prevWasTxQueue) merged++;
            if (w.startsWith("tm->") && prevWasTr) merged++;
            prevWasTxQueue = "tx_queue".equals(w);
            prevWasTr = "tr".equals(w);
        }
        return 7;
    }

    static String getPackageForUid(PackageManager pm, int uid) {
        if (pm == null || uid < 0) return null;
        try {
            String[] pkgs = pm.getPackagesForUid(uid);
            if (pkgs != null && pkgs.length > 0) return pkgs[0];
        } catch (Exception ignored) {}
        return null;
    }

    static String getAppNameForUid(PackageManager pm, int uid) {
        if (pm == null || uid < 0) return "unknown";
        try {
            String[] pkgs = pm.getPackagesForUid(uid);
            if (pkgs != null && pkgs.length > 0) {
                return pm.getApplicationLabel(
                    pm.getApplicationInfo(pkgs[0], 0)).toString();
            }
        } catch (Exception ignored) {}
        return "uid:" + uid;
    }

    // ── Passthrough (for allowed domains) ─────────────────────────────────

    private void passThrough(Socket client, byte[] peeked, int n, String domain) {
        try {
            InetAddress origin = resolveViaPublicDns(domain);
            if (origin == null || origin.isLoopbackAddress()) {
                Slog.e(TAG, "passThrough: bad origin for " + domain + " → " + origin);
                IoUtils.closeQuietly(client);
                return;
            }
            Socket originSock = new Socket(origin, mPort);
            client.setSoTimeout(0);
            originSock.setSoTimeout(0);
            originSock.getOutputStream().write(peeked, 0, n);

            mPool.execute(() -> {
                try { pipe(client.getInputStream(), originSock.getOutputStream()); }
                catch (Exception ignored) {}
                finally { IoUtils.closeQuietly(client); IoUtils.closeQuietly(originSock); }
            });
            mPool.execute(() -> {
                try { pipe(originSock.getInputStream(), client.getOutputStream()); }
                catch (Exception ignored) {}
                finally { IoUtils.closeQuietly(client); IoUtils.closeQuietly(originSock); }
            });
        } catch (Exception e) {
            Slog.e(TAG, "passThrough error for " + domain, e);
            IoUtils.closeQuietly(client);
        }
    }

    /**
     * Resolves a hostname via DNS-over-TCP to 1.1.1.1:53, bypassing the local
     * dnsmasq (whose iptables rule only redirects UDP port 53).
     * Falls back to system DNS if the TCP query fails, rejecting loopback results
     * to prevent the proxy from connecting back to itself.
     */
    static InetAddress resolveViaPublicDns(String hostname) {
        try {
            byte[] qname = encodeDnsName(hostname);
            int qlen = 12 + qname.length + 4;
            byte[] query = new byte[qlen];
            query[0] = 0x12; query[1] = 0x34;
            query[2] = 0x01; query[3] = 0x00;
            query[4] = 0x00; query[5] = 0x01;
            System.arraycopy(qname, 0, query, 12, qname.length);
            int p = 12 + qname.length;
            query[p++] = 0x00; query[p++] = 0x01;
            query[p++] = 0x00; query[p]   = 0x01;

            InetAddress dnsServer = InetAddress.getByAddress(new byte[]{1, 1, 1, 1});
            try (Socket tcp = new Socket()) {
                tcp.connect(new InetSocketAddress(dnsServer, 53), 3000);
                tcp.setSoTimeout(3000);
                OutputStream out = tcp.getOutputStream();
                out.write((qlen >> 8) & 0xFF);
                out.write(qlen & 0xFF);
                out.write(query);
                out.flush();

                InputStream in = tcp.getInputStream();
                int hi = in.read(), lo = in.read();
                if (hi < 0 || lo < 0) throw new IOException("EOF on response length");
                byte[] resp = new byte[(hi << 8) | lo];
                int off = 0;
                while (off < resp.length) {
                    int r = in.read(resp, off, resp.length - off);
                    if (r < 0) throw new IOException("EOF on response body");
                    off += r;
                }
                int ancount = ((resp[6] & 0xFF) << 8) | (resp[7] & 0xFF);
                int rpos = skipDnsName(resp, 12) + 4;
                for (int i = 0; i < ancount; i++) {
                    rpos = skipDnsName(resp, rpos);
                    int type = ((resp[rpos] & 0xFF) << 8) | (resp[rpos + 1] & 0xFF);
                    rpos += 8;
                    int rdlen = ((resp[rpos] & 0xFF) << 8) | (resp[rpos + 1] & 0xFF);
                    rpos += 2;
                    if (type == 1 && rdlen == 4) {
                        InetAddress addr =
                            InetAddress.getByAddress(Arrays.copyOfRange(resp, rpos, rpos + 4));
                        if (!addr.isLoopbackAddress()) return addr;
                    }
                    rpos += rdlen;
                }
            }
        } catch (Exception e) {
            Slog.w(TAG, "DNS-over-TCP failed for " + hostname, e);
        }
        try {
            InetAddress fallback = InetAddress.getByName(hostname);
            if (!fallback.isLoopbackAddress()) return fallback;
        } catch (Exception ignored) {}
        return null;
    }

    private static byte[] encodeDnsName(String hostname) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (String label : hostname.split("\\.")) {
            byte[] lb = label.getBytes(StandardCharsets.US_ASCII);
            baos.write(lb.length);
            baos.write(lb);
        }
        baos.write(0);
        return baos.toByteArray();
    }

    private static int skipDnsName(byte[] buf, int pos) {
        while (pos < buf.length) {
            int b = buf[pos] & 0xFF;
            if (b == 0) return pos + 1;
            if ((b & 0xC0) == 0xC0) return pos + 2;
            pos += b + 1;
        }
        return pos;
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static void pipe(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
            out.flush();
        }
    }
}
