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

import android.app.ActivityManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Environment;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.os.UserManager;
import android.provider.Settings;
import android.util.ArrayMap;
import android.util.ArraySet;
import android.util.AtomicFile;
import android.util.Slog;
import android.util.Xml;

import com.android.internal.os.BackgroundThread;
import com.android.server.SystemService;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManagerFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import libcore.io.IoUtils;
import lineageos.app.LineageContextConstants;
import lineageos.firewall.IFirewallService;

import static android.net.NetworkCapabilities.MIN_TRANSPORT;
import static android.net.NetworkCapabilities.MAX_TRANSPORT;

import android.net.Network;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.IDnsResolver;
import android.net.shared.PrivateDnsConfig;
import com.android.server.connectivity.MockableSystemProperties;
import com.android.server.connectivity.DnsManager;
import com.android.server.LocalServices;
import com.android.server.UiModeManagerInternal;

import fi.iki.elonen.NanoHTTPD;

public class FirewallService extends LineageSystemService {

    private static final String TAG = "FirewallService";
    private static final boolean DEBUG_FIREWALL = true;

    private static final String FILE_NAME = "list-domains.xml";
    private static final String TAG_LISTED_DOMAINS = "list-domains";
    private static final String TAG_DOMAIN = "domain";
    private static final String ATTRIBUTE_NAME = "name";
    private static final String COMMON_DNS = "1.1.1.1";

    private int mUserId;
    private Context mContext;
    private UiModeManagerInternal mUiModeMgr;

    private AtomicFile mFile;
    private final FirewallHandler mHandler;

    private HttpWebServer mHttpWebServer;
    private HttpsWebServer mHttpsWebServer;
    private boolean isWebServerEnabled;

    private final ArrayList<String> mDomainsList = new ArrayList<String>();

    public FirewallService(Context context) {
        super(context);

        mContext = context;
        mHandler = new FirewallHandler(BackgroundThread.getHandler().getLooper());
        mUserId = ActivityManager.getCurrentUser();
        mUiModeMgr = LocalServices.getService(UiModeManagerInternal.class);
    }

    @Override
    public String getFeatureDeclaration() {
        return LineageContextConstants.Features.HARDWARE_ABSTRACTION;
    }

    @Override
    public void onStart() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "Starting FirewallService");
        publishBinderService(LineageContextConstants.VOLLA_FIREWALL_SERVICE, mService);
    }

    @Override
    public void onUnlockUser(int userHandle) {
        if (DEBUG_FIREWALL) Slog.v(TAG, "onUnlockUser() mUserId:" + userHandle);
        if (!UserManager.get(mContext).isManagedProfile(userHandle)) {
            if (DEBUG_FIREWALL) Slog.v(TAG, "onUnlockUser() is NOT ManagedProfile");
            mUserId = userHandle;
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_APPS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_SYSTEM_SERVICES_READY) {
            if (DEBUG_FIREWALL) Slog.v(TAG, "onBootPhase PHASE_SYSTEM_SERVICES_READY");
            if (isActivate()) {
                SystemProperties.set("ctl.start", "volla.dnsmasq");
                activateWebServer(true);
            }
        }
    }

    @Override
    public void onSwitchUser(int userHandle) {
        if (DEBUG_FIREWALL) Slog.v(TAG, "onSwitchUser() mUserId:" + userHandle);
        if (!UserManager.get(mContext).isManagedProfile(userHandle)) {
            if (DEBUG_FIREWALL) Slog.v(TAG, "onSwitchUser() is NOT ManagedProfile");
            mUserId = userHandle;
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_APPS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    @Override
    public void onStopUser(int userHandle) {
        if (DEBUG_FIREWALL) Slog.v(TAG, "onStopUser() userHandle:" + userHandle);
        if (mUserId == userHandle) {
            mUserId = ActivityManager.getCurrentUser();
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_APPS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    private void activateWebServer(boolean enable) {
        if (!isWebServerEnabled && enable) {
            try {
                mHttpWebServer = new HttpWebServer();
                mHttpWebServer.start();
                mHttpsWebServer = new HttpsWebServer();
                mHttpsWebServer.start();
                isWebServerEnabled = true;
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (isWebServerEnabled && !enable) {
            if (mHttpWebServer != null)
                mHttpWebServer.stop();
            if (mHttpsWebServer != null)
                mHttpsWebServer.stop();
            isWebServerEnabled = false;
        }
    }

    private void initLockedApps() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "initLockedApps(" + mUserId + ")");
        mFile = new AtomicFile(getFile());
        readState();
    }

    private File getFile() {
        File file = new File(Environment.getDataSystemCeDirectory(mUserId), FILE_NAME);
        if (DEBUG_FIREWALL) Slog.v(TAG, "getFile(): " + file.getAbsolutePath());
        return file;
    }

    private void readState() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "readState()");
        mDomainsList.clear();
        try (FileInputStream in = mFile.openRead()) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(in, null);
            parseXml(parser);
            if (DEBUG_FIREWALL) Slog.v(TAG, "Read " + FILE_NAME + " successfully");
        } catch (FileNotFoundException e) {
            if (DEBUG_FIREWALL) Slog.v(TAG, FILE_NAME + " not found");
            Slog.i(TAG, FILE_NAME + " not found");
        } catch (XmlPullParserException | IOException e) {
            throw new IllegalStateException("Failed to parse " + FILE_NAME + ": " + mFile, e);
        }
    }

    private void parseXml(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        int type;
        int depth;
        int innerDepth = parser.getDepth() + 1;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                && ((depth = parser.getDepth()) >= innerDepth || type != XmlPullParser.END_TAG)) {
            if (depth > innerDepth || type != XmlPullParser.START_TAG) {
                continue;
            }
            if (parser.getName().equals(TAG_LISTED_DOMAINS)) {
                parsePackages(parser);
                return;
            }
        }
        Slog.w(TAG, "Missing <" + TAG_LISTED_DOMAINS + "> in " + FILE_NAME);
    }

    private void parsePackages(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        int type;
        int depth;
        int innerDepth = parser.getDepth() + 1;
        boolean writeAfter = false;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                && ((depth = parser.getDepth()) >= innerDepth || type != XmlPullParser.END_TAG)) {
            if (depth > innerDepth || type != XmlPullParser.START_TAG) {
                continue;
            }
            if (parser.getName().equals(TAG_DOMAIN)) {
                String domainName = parser.getAttributeValue(null, ATTRIBUTE_NAME);
                mDomainsList.add(domainName);
                if (DEBUG_FIREWALL) Slog.v(TAG, "parsePackages(): domainName=" + domainName);
            }
        }
    }

    private void writeState() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "writeState()");

        FileOutputStream out = null;
        try {
            out = mFile.startWrite();
            XmlSerializer serializer = Xml.newSerializer();
            serializer.setOutput(out, StandardCharsets.UTF_8.name());
            serializer.setFeature(
                    "http://xmlpull.org/v1/doc/features.html#indent-output", true);
            serializer.startDocument(null, true);
            serializeLockedApps(serializer);
            serializer.endDocument();
            mFile.finishWrite(out);
            if (DEBUG_FIREWALL) Slog.v(TAG, "Wrote " + FILE_NAME + " successfully");
        } catch (IllegalArgumentException | IllegalStateException | IOException e) {
            Slog.wtf(TAG, "Failed to write " + FILE_NAME + ", restoring backup", e);
            if (out != null) {
                mFile.failWrite(out);
            }
        } finally {
            IoUtils.closeQuietly(out);
        }
    }

    private void serializeLockedApps(XmlSerializer serializer) throws IOException {
        serializer.startTag(null, TAG_LISTED_DOMAINS);
        for (String domain : mDomainsList) {
            serializer.startTag(null, TAG_DOMAIN);
            serializer.attribute(null, ATTRIBUTE_NAME, domain);
            serializer.endTag(null, TAG_DOMAIN);
        }
        serializer.endTag(null, TAG_LISTED_DOMAINS);
    }

    private void resetDnsConf() {
        ArrayList<String> confLines = new ArrayList<String>();
        boolean blacklist = isBlacklistMode();
        File dnsmasqDir = new File(Environment.getDataSystemCeDirectory(mUserId), "dnsmasq");
        if (!dnsmasqDir.exists() && !dnsmasqDir.mkdirs())
            Slog.e(TAG, "Error while creating dnsmasq directory: " + dnsmasqDir);
        confLines.add("# Volla firewall fonfiguration file for dnsmasq.");
        if (mDomainsList.size() > 0) {
            for (String domain : mDomainsList) {
                if (blacklist)
                    confLines.add("address=/" + domain + "/127.0.0.1");
                else
                    confLines.add("server=/" + domain + "/" + COMMON_DNS);
            }
            if (!blacklist)
                confLines.add("address=/#/127.0.0.1");
        }
        try {
            Files.write(Paths.get(dnsmasqDir.getAbsolutePath() + "/dns.conf"),
              confLines, StandardCharsets.UTF_8);
        } catch (IOException e) {
            Slog.wtf(TAG, "Failed to write dnsmasq config", e);
        }
        if (isActivate())
            SystemProperties.set("ctl.restart", "volla.dnsmasq");
    }

    public void activate(boolean enable) {
        SystemProperties.set("persist.volla.firewall.enable", enable ? "true" : "false");
        if (enable) {
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
            SystemProperties.set("ctl.start", "volla.dnsmasq");
        } else {
            SystemProperties.set("ctl.stop", "volla.dnsmasq");
        }
        activateWebServer(enable);
        ConnectivityManager connectivityManager = (ConnectivityManager)mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        IDnsResolver resolver = IDnsResolver.Stub
                .asInterface(ServiceManager.getService("dnsresolver"));
        MockableSystemProperties systemProperties = new MockableSystemProperties();
        DnsManager dnsManager = new DnsManager(mContext, resolver, systemProperties);
        Network network = connectivityManager.getActiveNetwork();
        LinkProperties linkProperties = connectivityManager.getActiveLinkProperties();
        PrivateDnsConfig cfg = dnsManager.getPrivateDnsConfig();
        if (network != null) {
            dnsManager.updatePrivateDns(network, cfg);
            dnsManager.updateTransportsForNetwork(network.netId, IntStream.range(MIN_TRANSPORT, MAX_TRANSPORT).toArray());
            dnsManager.noteDnsServersForNetwork(network.netId, linkProperties);
            dnsManager.sendDnsConfigurationForNetwork(network.netId);
            dnsManager.setDefaultDnsSystemProperties(linkProperties.getDnsServers());
            dnsManager.flushVmDnsCache();
            dnsManager.updatePrivateDnsStatus(network.netId, linkProperties);
        }
    }

    public boolean isActivate() {
        return SystemProperties.getBoolean("persist.volla.firewall.enable", false);
    }

    public void blacklistMode(boolean enable) {
        SystemProperties.set("persist.volla.blacklist.enable", enable ? "true" : "false");
        if (isActivate())
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
    }

    public boolean isBlacklistMode() {
        return SystemProperties.getBoolean("persist.volla.blacklist.enable", false);
    }

    private void addDomainToList(String domain) {
        if (DEBUG_FIREWALL) Slog.v(TAG, "addDomainToList domain:" + domain);
        if (!mDomainsList.contains(domain)) {
            mDomainsList.add(domain);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_STATE);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    private void removeDomainFromList(String domain) {
        if (mDomainsList.contains(domain)) {
            mDomainsList.remove(domain);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_STATE);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    public boolean isDomainOnList(String domain) {
        return mDomainsList.contains(domain);
    }

    private List<String> getDomainsList() {
        return mDomainsList;
    }

    private int getDomainsListCount() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "Number of domains on list: " + mDomainsList.size());
        return mDomainsList.size();
    }

    private void clearDomainList() {
        if (!mDomainsList.isEmpty()) {
            mDomainsList.clear();
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_STATE);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    private String getBlockedPage() {
        InputStream inputStream = mContext.getResources().openRawResource(org.lineageos.platform.internal.R.raw.firewall);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        byte buf[] = new byte[1024];
        int len;
        try {
            while ((len = inputStream.read(buf)) != -1) {
                outputStream.write(buf, 0, len);
            }
            outputStream.close();
            inputStream.close();
        } catch (IOException e) {
            return "";
        }
        return outputStream.toString()
                .replace("BLOCKED_TEXT", mContext.getResources().getString(org.lineageos.platform.internal.R.string.firewall_text))
                .replace("DARKMODE_STATUS", String.valueOf(mUiModeMgr.isNightMode()));
    }

    private final IBinder mService = new IFirewallService.Stub() {
        @Override
        public void activate(boolean enable) {
            FirewallService.this.activate(enable);
        }

        @Override
        public boolean isActivate() {
            return FirewallService.this.isActivate();
        }

        @Override
        public void blacklistMode(boolean enable) {
            FirewallService.this.blacklistMode(enable);
        }

        @Override
        public boolean isBlacklistMode() {
            return FirewallService.this.isBlacklistMode();
        }

        @Override
        public void addDomainToList(String domain) {
            FirewallService.this.addDomainToList(domain);
        }

        @Override
        public void removeDomainFromList(String domain) {
            FirewallService.this.removeDomainFromList(domain);
        }

        @Override
        public boolean isDomainOnList(String domain) {
            return FirewallService.this.isDomainOnList(domain);
        }

        @Override
        public int getDomainsListCount() {
            return FirewallService.this.getDomainsListCount();
        }

        @Override
        public List<String> getDomainsList() {
            return FirewallService.this.getDomainsList();
        }

        @Override
        public void clearDomainList() {
            FirewallService.this.clearDomainList();
        }
    };

    private class FirewallHandler extends Handler {

        public static final int MSG_INIT_APPS = 0;
        public static final int MSG_WRITE_STATE = 1;
        public static final int MSG_WRITE_CONF = 2;

        public FirewallHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(android.os.Message msg) {
            switch (msg.what) {
                case MSG_INIT_APPS:
                    initLockedApps();
                    break;
                case MSG_WRITE_STATE:
                    writeState();
                    break;
                case MSG_WRITE_CONF:
                    resetDnsConf();
                    break;
                default:
                    Slog.w(TAG, "Unknown message:" + msg.what);
            }
        }
    }

    public class HttpWebServer extends NanoHTTPD {
        public HttpWebServer() {
            super(80);
        }

        @Override
        public Response serve(IHTTPSession session) {
            return newFixedLengthResponse(getBlockedPage());
        }
    }

    public class HttpsWebServer extends NanoHTTPD {
        public HttpsWebServer() {
            super(443);
            KeyStore keyStore = null;
            try {
                keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                File initialFile = new File("/system/etc/localhost.bks");
                InputStream keyStoreStream = new FileInputStream(initialFile);
                keyStore.load(keyStoreStream, "myKeyStorePass".toCharArray());
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(keyStore, "myKeyStorePass".toCharArray());
                makeSecure(NanoHTTPD.makeSSLSocketFactory(keyStore, keyManagerFactory), null);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        @Override
        public Response serve(IHTTPSession session) {
            return newFixedLengthResponse(getBlockedPage());
        }
    }
}
