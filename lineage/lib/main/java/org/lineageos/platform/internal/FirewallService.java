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

import static android.net.NetworkPolicyManager.POLICY_REJECT_ALL;

import android.app.ActivityManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.NetworkPolicyManager;
import android.net.Uri;
import android.os.Environment;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
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
import android.view.Display;

import com.android.internal.os.BackgroundThread;
import com.android.server.SystemService;
import com.android.server.UiModeManagerInternal;
import com.android.server.LocalServices;

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
import java.net.InetSocketAddress;
import java.net.Socket;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.android.internal.org.bouncycastle.asn1.x509.BasicConstraints;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.asn1.x509.GeneralName;
import com.android.internal.org.bouncycastle.asn1.x509.GeneralNames;
import com.android.internal.org.bouncycastle.asn1.x509.KeyUsage;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1Set;
import com.android.internal.org.bouncycastle.asn1.ASN1String;
import com.android.internal.org.bouncycastle.asn1.DERBitString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERSet;
import com.android.internal.org.bouncycastle.asn1.DERIA5String;
import com.android.internal.org.bouncycastle.asn1.DERUTF8String;
import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.asn1.x509.ExtensionsGenerator;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.asn1.x509.TBSCertificate;
import com.android.internal.org.bouncycastle.asn1.x509.Time;
import com.android.internal.org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import java.io.ByteArrayInputStream;
import java.security.Signature;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Base64;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.security.auth.x500.X500Principal;
import java.util.stream.IntStream;
import java.util.Set;

import libcore.io.IoUtils;
import lineageos.app.LineageContextConstants;
import lineageos.firewall.DomainListInfo;
import lineageos.firewall.IFirewallService;

import static android.provider.Settings.Global.PRIVATE_DNS_DEFAULT_MODE;


public class FirewallService extends LineageSystemService {

    private static final String TAG = "FirewallService";
    private static final boolean DEBUG_FIREWALL = true;

    private static final String DOMAINS_FILE_NAME = "list-domains.xml";
    private static final String TAG_LISTED_DOMAINS = "list-domains";
    private static final String TAG_DOMAIN = "domain";
    private static final String APPS_FILE_NAME = "list-restrictedapps.xml";
    private static final String TAG_LISTED_APPS = "list-restrictedapps";
    private static final String TAG_APP = "app";
    private static final String DOMAIN_LISTS_FILE_NAME = "list-domainlists.xml";
    private static final String TAG_LISTED_DOMAIN_LISTS = "list-domainlists";
    private static final String TAG_DOMAIN_LIST = "domain-list";
    private static final String ATTRIBUTE_NAME = "name";
    private static final String ATTRIBUTE_ID = "id";
    private static final String ATTRIBUTE_TITLE = "title";
    private static final String ATTRIBUTE_URL = "url";
    private static final String ATTRIBUTE_VERSION = "version";
    private static final String ATTRIBUTE_BLACKLIST = "isBlacklist";
    private static final String COMMON_DNS = "208.67.220.220";
    private static final long AIRPLANE_RECONNECT_TIMEOUT_MS = 60_000L;
    private static final long AIRPLANE_RECONNECT_POLL_MS = 3_000L;
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String CA_KEY_ALIAS = "volla_firewall_ca";
    private static final String CA_CERT_FILE = "firewall_ca.der";
    private static final long LEAF_CERT_TTL_MS = 3_600_000L;
    private static final String PROP_ALERT_MODE  = "persist.volla.firewall.alertmode";
    private static final String PKG_SYSTEM       = "android";
    private static final String ALLOWED_FILE_NAME    = "list-allowed.xml";
    private static final String TAG_ALLOWED_DOMAINS  = "list-allowed";
    private static final String TAG_ALLOWED_DOMAIN   = "allowed-domain";
    private static final String ATTRIBUTE_EXPIRY     = "expiry";
    private static final long   ALLOW_TEMP_MS        = 5 * 60 * 1000L;
    private static final String NOTIF_CHANNEL_ID     = "firewall_alerts";
    private static final String ACTION_DENY          = "lineageos.firewall.DENY";
    private static final String ACTION_ALLOW_TEMP    = "lineageos.firewall.ALLOW_TEMP";
    private static final String ACTION_ALLOW_PERM    = "lineageos.firewall.ALLOW_PERM";
    private static final String EXTRA_DOMAIN         = "domain";
    private static final String EXTRA_PKG            = "pkg";
    private static final String EXTRA_NOTIF_ID       = "notif_id";
    private static final AlgorithmIdentifier ECDSA_SHA256_ALG =
        new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"));

    private int mUserId;
    private Context mContext;
    private UiModeManagerInternal mUiModeMgr;
    private PackageManager mPackageManager;
    private NetworkPolicyManager mPolicyManager;

    private AtomicFile mDomainsFile;
    private AtomicFile mAppsFile;
    private AtomicFile mDomainListsFile;
    private final FirewallHandler mHandler;

    private TcpProxy mHttpProxy;
    private TcpProxy mHttpsProxy;
    private boolean isWebServerEnabled;

    private AtomicFile mAllowedFile;
    private final ArrayMap<String, Long> mAllowedDomains = new ArrayMap<>();
    private BroadcastReceiver mNotifActionReceiver;
    private FirewallBlockDatabase mBlockDb;

    private final ArrayList<String> mManualDomainsList = new ArrayList<String>();
    private final ArrayList<String> mAppsList = new ArrayList<String>();
    private final ArrayList<DomainListInfo> mDomainListInfoList = new ArrayList<DomainListInfo>();
    private final ArrayMap<String, List<String>> mPendingDomainListAdds = new ArrayMap<>();
    private long mAirplaneRefreshDeadline = 0;

    private X509Certificate mCACert;
    private PrivateKey mCAPrivateKey;
    private SSLContext mSSLContext;
    private final Object mCertLock = new Object();
    private final ArrayMap<String, LeafCertEntry> mLeafCertCache = new ArrayMap<>();

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
    public void onUserUnlocking(@NonNull TargetUser targetUser) {
        int userHandle = targetUser.getUserIdentifier();
        if (DEBUG_FIREWALL) Slog.v(TAG, "onUserUnlocking() mUserId:" + userHandle);
        if (!UserManager.get(mContext).isManagedProfile(userHandle)) {
            if (DEBUG_FIREWALL) Slog.v(TAG, "onUserUnlocking() is NOT ManagedProfile");
            mUserId = userHandle;
            mAllowedFile = new AtomicFile(new File(
                Environment.getDataSystemCeDirectory(mUserId), ALLOWED_FILE_NAME));
            mBlockDb = new FirewallBlockDatabase(mContext,
                new File(Environment.getDataSystemCeDirectory(mUserId), "firewall_events.db")
                    .getAbsolutePath());
            setupNotificationChannel();
            registerNotifActionReceiver();
            initCA();
            if (isActivate()) {
                activate(true);
            }
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_DOMAINS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_APPS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_DOMAIN_LISTS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_ALLOWED);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_SYSTEM_SERVICES_READY) {
            if (DEBUG_FIREWALL) Slog.v(TAG, "onBootPhase PHASE_SYSTEM_SERVICES_READY");
            mPackageManager = mContext.getPackageManager();
            mPolicyManager = (NetworkPolicyManager) mContext
                .getSystemService(Context.NETWORK_POLICY_SERVICE);

            IntentFilter airplaneFilter = new IntentFilter(Intent.ACTION_AIRPLANE_MODE_CHANGED);
            mContext.registerReceiver(mAirplaneModeReceiver, airplaneFilter);
        }
    }

    private boolean isConnectedToNetwork() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(COMMON_DNS, 53), 2000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private final Runnable mConnectivityCheckRunnable = new Runnable() {
        @Override
        public void run() {
            if (isConnectedToNetwork() || System.currentTimeMillis() >= mAirplaneRefreshDeadline) {
                if (DEBUG_FIREWALL) Slog.v(TAG, "airplane mode: reactivating firewall");
                activate(true);
            } else {
                mHandler.postDelayed(this, AIRPLANE_RECONNECT_POLL_MS);
            }
        }
    };

    private final BroadcastReceiver mAirplaneModeReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!isActivate()) return;
            if (DEBUG_FIREWALL) Slog.v(TAG, "airplane mode changed, refreshing firewall");
            activate(false);
            mAirplaneRefreshDeadline = System.currentTimeMillis() + AIRPLANE_RECONNECT_TIMEOUT_MS;
            mHandler.removeCallbacks(mConnectivityCheckRunnable);
            mHandler.postDelayed(mConnectivityCheckRunnable, AIRPLANE_RECONNECT_POLL_MS);
        }
    };

    @Override
    public void onUserSwitching(@Nullable TargetUser from, @NonNull TargetUser to) {
        int userHandle = to.getUserIdentifier();
        if (DEBUG_FIREWALL) Slog.v(TAG, "onSwitchUser() mUserId:" + userHandle);
        if (!UserManager.get(mContext).isManagedProfile(userHandle)) {
            if (DEBUG_FIREWALL) Slog.v(TAG, "onSwitchUser() is NOT ManagedProfile");
            mUserId = userHandle;
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_DOMAINS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_APPS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_DOMAIN_LISTS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    @Override
    public void onUserStopping(@NonNull TargetUser targetUser) {
        int userHandle = targetUser.getUserIdentifier();
        if (DEBUG_FIREWALL) Slog.v(TAG, "onStopUser() userHandle:" + userHandle);
        if (mUserId == userHandle) {
            mUserId = ActivityManager.getCurrentUser();
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_DOMAINS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_APPS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_DOMAIN_LISTS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    private void activateWebServer(boolean enable) {
        if (!isWebServerEnabled && enable) {
            try {
                mHttpProxy = new TcpProxy(80, null, this::getBlockedPage,
                    this::onDomainBlocked, mPackageManager, this::isAllowed);
                mHttpProxy.start();
                mHttpsProxy = new TcpProxy(443, mSSLContext, this::getBlockedPage,
                    this::onDomainBlocked, mPackageManager, this::isAllowed);
                mHttpsProxy.start();
                isWebServerEnabled = true;
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (isWebServerEnabled && !enable) {
            if (mHttpProxy != null)
                mHttpProxy.stop();
            if (mHttpsProxy != null)
                mHttpsProxy.stop();
            isWebServerEnabled = false;
        }
    }

    private static final class LeafCertEntry {
        final X509Certificate cert;
        final PrivateKey key;
        final long expiresAt;

        LeafCertEntry(X509Certificate cert, PrivateKey key, long expiresAt) {
            this.cert = cert;
            this.key = key;
            this.expiresAt = expiresAt;
        }
    }

    private void initCA() {
        Slog.i(TAG, "initCA: starting");
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            Slog.i(TAG, "initCA: keystore opened, alias exists=" + ks.containsAlias(CA_KEY_ALIAS));
            if (!ks.containsAlias(CA_KEY_ALIAS)) {
                Slog.i(TAG, "initCA: generating EC key pair in TEE");
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
                kpg.initialize(new KeyGenParameterSpec.Builder(
                    CA_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .build());
                kpg.generateKeyPair();
                Slog.i(TAG, "initCA: key pair generated");
            }
            mCAPrivateKey = (PrivateKey) ks.getKey(CA_KEY_ALIAS, null);
            Slog.i(TAG, "initCA: private key=" + (mCAPrivateKey != null ? mCAPrivateKey.getClass().getName() : "null"));
            PublicKey caPub = ks.getCertificate(CA_KEY_ALIAS).getPublicKey();
            Slog.i(TAG, "initCA: public key algorithm=" + caPub.getAlgorithm());

            File caCertFile = new File(Environment.getDataSystemDirectory(), CA_CERT_FILE);
            Slog.i(TAG, "initCA: cert file=" + caCertFile + " exists=" + caCertFile.exists());
            if (caCertFile.exists()) {
                byte[] der = Files.readAllBytes(Paths.get(caCertFile.getAbsolutePath()));
                Slog.i(TAG, "initCA: loading existing CA cert (" + der.length + " bytes)");
                mCACert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            } else {
                Slog.i(TAG, "initCA: building new CA cert with BouncyCastle");
                X500Name caName = new X500Name("CN=Volla Firewall CA");
                Date now = new Date();
                Date expiry = new Date(now.getTime() + 10L * 365 * 24 * 60 * 60 * 1000);
                ExtensionsGenerator extGen = new ExtensionsGenerator();
                extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
                extGen.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
                mCACert = buildSignedCert(caName, caName, BigInteger.ONE, now, expiry,
                    caPub, extGen);
                Slog.i(TAG, "initCA: CA cert built, subject=" + mCACert.getSubjectDN());
                Files.write(Paths.get(caCertFile.getAbsolutePath()), mCACert.getEncoded());
                Slog.i(TAG, "initCA: CA cert written to " + caCertFile);
                installToSystemCaStore(mCACert);
            }
            long hash = canonicalSubjectHash(mCACert.getSubjectX500Principal());
            File userCaFile = new File(Environment.getDataSystemDirectory(), String.format("%08x.0", hash));
            if (!userCaFile.exists()) {
                Slog.i(TAG, "initCA: CA missing from user store, reinstalling: " + userCaFile);
                installToSystemCaStore(mCACert);
            }
            mSSLContext = SSLContext.getInstance("TLS");
            mSSLContext.init(new KeyManager[]{new SNIKeyManager()}, null, null);
            Slog.i(TAG, "initCA: done, CA=" + mCACert.getSubjectDN()
                + " valid until " + mCACert.getNotAfter());
        } catch (Exception e) {
            Slog.e(TAG, "initCA: FAILED", e);
        }
    }

    private X509Certificate buildSignedCert(X500Name issuer, X500Name subject, BigInteger serial,
            Date notBefore, Date notAfter, PublicKey pubKey, ExtensionsGenerator extGen)
            throws Exception {
        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(serial));
        tbsGen.setSignature(ECDSA_SHA256_ALG);
        tbsGen.setIssuer(issuer);
        tbsGen.setStartDate(new Time(notBefore));
        tbsGen.setEndDate(new Time(notAfter));
        tbsGen.setSubject(subject);
        tbsGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
        if (extGen != null) {
            tbsGen.setExtensions(extGen.generate());
        }
        TBSCertificate tbsCert = tbsGen.generateTBSCertificate();

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(mCAPrivateKey);
        sig.update(tbsCert.getEncoded());
        byte[] sigBytes = sig.sign();

        ASN1EncodableVector cv = new ASN1EncodableVector();
        cv.add(tbsCert);
        cv.add(ECDSA_SHA256_ALG);
        cv.add(new DERBitString(sigBytes));
        return (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(new DERSequence(cv).getEncoded()));
    }

    private void installToSystemCaStore(X509Certificate cert) {
        try {
            long h = canonicalSubjectHash(cert.getSubjectX500Principal());
            File certFile = new File(Environment.getDataSystemDirectory(), String.format("%08x.0", h));
            if (!certFile.exists()) {
                byte[] pem = ("-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
                    + "\n-----END CERTIFICATE-----\n").getBytes(StandardCharsets.UTF_8);
                Files.write(certFile.toPath(), pem);
                certFile.setReadable(true, false);
                Slog.i(TAG, "CA installed to user store: " + certFile);
            }
        } catch (Exception e) {
            Slog.e(TAG, "Failed to install CA to system store", e);
        }
    }

    // OpenSSL X509_NAME_hash_old: MD5 of the raw subject SEQUENCE DER bytes, first 4 bytes LE.
    // This matches what Android Settings uses when installing a CA certificate.
    private static long canonicalSubjectHash(X500Principal principal) throws Exception {
        byte[] encoded = principal.getEncoded(); // raw SEQUENCE DER
        byte[] hash = MessageDigest.getInstance("MD5").digest(encoded);
        return (hash[0] & 0xFFL) | ((hash[1] & 0xFFL) << 8)
             | ((hash[2] & 0xFFL) << 16) | ((hash[3] & 0xFFL) << 24);
    }

    private LeafCertEntry generateLeafCert(String hostname) {
        synchronized (mCertLock) {
            LeafCertEntry cached = mLeafCertCache.get(hostname);
            if (cached != null && System.currentTimeMillis() < cached.expiresAt) {
                return cached;
            }
        }
        if (mCACert == null || mCAPrivateKey == null) return null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair leafKp = kpg.generateKeyPair();

            X500Name issuer = X500Name.getInstance(mCACert.getSubjectX500Principal().getEncoded());
            X500Name subject = new X500Name("CN=" + hostname);
            Date now = new Date();
            Date expiry = new Date(now.getTime() + 24L * 60 * 60 * 1000);
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, hostname)));
            X509Certificate leafCert = buildSignedCert(issuer, subject,
                BigInteger.valueOf(System.currentTimeMillis()), now, expiry,
                leafKp.getPublic(), extGen);

            LeafCertEntry entry = new LeafCertEntry(leafCert, leafKp.getPrivate(),
                System.currentTimeMillis() + LEAF_CERT_TTL_MS);
            synchronized (mCertLock) {
                mLeafCertCache.put(hostname, entry);
            }
            return entry;
        } catch (Exception e) {
            Slog.e(TAG, "Failed to generate leaf cert for " + hostname, e);
            return null;
        }
    }

    private void initLockedDomains() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "initLockedDomains(" + mUserId + ")");
        mDomainsFile = new AtomicFile(getDomainsFile());
        readDomainsState();
    }

    private File getDomainsFile() {
        File file = new File(Environment.getDataSystemCeDirectory(mUserId), DOMAINS_FILE_NAME);
        if (DEBUG_FIREWALL) Slog.v(TAG, "getDomainsFile(): " + file.getAbsolutePath());
        return file;
    }

    private void readDomainsState() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "readDomainsState()");
        mManualDomainsList.clear();
        try (FileInputStream in = mDomainsFile.openRead()) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(in, null);
            parseDomainsXml(parser);
            if (DEBUG_FIREWALL) Slog.v(TAG, "Read " + DOMAINS_FILE_NAME + " successfully");
        } catch (FileNotFoundException e) {
            if (DEBUG_FIREWALL) Slog.v(TAG, DOMAINS_FILE_NAME + " not found");
            Slog.i(TAG, DOMAINS_FILE_NAME + " not found");
        } catch (XmlPullParserException | IOException e) {
            throw new IllegalStateException("Failed to parse " + DOMAINS_FILE_NAME + ": " + mDomainsFile, e);
        }
    }

    private void parseDomainsXml(XmlPullParser parser) throws IOException,
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
                parseDomains(parser);
                return;
            }
        }
        Slog.w(TAG, "Missing <" + TAG_LISTED_DOMAINS + "> in " + DOMAINS_FILE_NAME);
    }

    private void parseDomains(XmlPullParser parser) throws IOException,
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
                mManualDomainsList.add(domainName);
                if (DEBUG_FIREWALL) Slog.v(TAG, "parseDomains(): domainName=" + domainName);
            }
        }
    }

    private void writeDomainsState() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "writeDomainsState()");

        FileOutputStream out = null;
        try {
            out = mDomainsFile.startWrite();
            XmlSerializer serializer = Xml.newSerializer();
            serializer.setOutput(out, StandardCharsets.UTF_8.name());
            serializer.setFeature(
                    "http://xmlpull.org/v1/doc/features.html#indent-output", true);
            serializer.startDocument(null, true);
            serializeDomains(serializer);
            serializer.endDocument();
            mDomainsFile.finishWrite(out);
            if (DEBUG_FIREWALL) Slog.v(TAG, "Wrote " + DOMAINS_FILE_NAME + " successfully");
        } catch (IllegalArgumentException | IllegalStateException | IOException e) {
            Slog.wtf(TAG, "Failed to write " + DOMAINS_FILE_NAME + ", restoring backup", e);
            if (out != null) {
                mDomainsFile.failWrite(out);
            }
        } finally {
            IoUtils.closeQuietly(out);
        }
    }

    private void serializeDomains(XmlSerializer serializer) throws IOException {
        serializer.startTag(null, TAG_LISTED_DOMAINS);
        ArrayList<String> newDomainsList = new ArrayList<>(mManualDomainsList);
        for (String domain : newDomainsList) {
            serializer.startTag(null, TAG_DOMAIN);
            serializer.attribute(null, ATTRIBUTE_NAME, domain);
            serializer.endTag(null, TAG_DOMAIN);
        }
        serializer.endTag(null, TAG_LISTED_DOMAINS);
    }

    private void initRestrictedApps() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "initRestrictedApps(" + mUserId + ")");
        mAppsFile = new AtomicFile(getAppsFile());
        readAppsState();
    }

    private File getAppsFile() {
        File file = new File(Environment.getDataSystemCeDirectory(mUserId), APPS_FILE_NAME);
        if (DEBUG_FIREWALL) Slog.v(TAG, "getAppsFile(): " + file.getAbsolutePath());
        return file;
    }

    private void readAppsState() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "readAppsState()");
        mAppsList.clear();
        try (FileInputStream in = mAppsFile.openRead()) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(in, null);
            parseAppsXml(parser);
            if (DEBUG_FIREWALL) Slog.v(TAG, "Read " + APPS_FILE_NAME + " successfully");
        } catch (FileNotFoundException e) {
            if (DEBUG_FIREWALL) Slog.v(TAG, APPS_FILE_NAME + " not found");
            Slog.i(TAG, APPS_FILE_NAME + " not found");
        } catch (XmlPullParserException | IOException e) {
            throw new IllegalStateException("Failed to parse " + APPS_FILE_NAME + ": " + mAppsFile, e);
        }
    }

    private void parseAppsXml(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        int type;
        int depth;
        int innerDepth = parser.getDepth() + 1;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                && ((depth = parser.getDepth()) >= innerDepth || type != XmlPullParser.END_TAG)) {
            if (depth > innerDepth || type != XmlPullParser.START_TAG) {
                continue;
            }
            if (parser.getName().equals(TAG_LISTED_APPS)) {
                parseApps(parser);
                return;
            }
        }
        Slog.w(TAG, "Missing <" + TAG_LISTED_APPS + "> in " + APPS_FILE_NAME);
    }

    private void parseApps(XmlPullParser parser) throws IOException,
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
            if (parser.getName().equals(TAG_APP)) {
                String appName = parser.getAttributeValue(null, ATTRIBUTE_NAME);
                mAppsList.add(appName);
                if (DEBUG_FIREWALL) Slog.v(TAG, "parseApps(): appName=" + appName);
            }
        }
    }

    private void writeAppsState() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "writeAppsState()");

        FileOutputStream out = null;
        try {
            out = mAppsFile.startWrite();
            XmlSerializer serializer = Xml.newSerializer();
            serializer.setOutput(out, StandardCharsets.UTF_8.name());
            serializer.setFeature(
                    "http://xmlpull.org/v1/doc/features.html#indent-output", true);
            serializer.startDocument(null, true);
            serializeApps(serializer);
            serializer.endDocument();
            mAppsFile.finishWrite(out);
            if (DEBUG_FIREWALL) Slog.v(TAG, "Wrote " + APPS_FILE_NAME + " successfully");
        } catch (IllegalArgumentException | IllegalStateException | IOException e) {
            Slog.wtf(TAG, "Failed to write " + APPS_FILE_NAME + ", restoring backup", e);
            if (out != null) {
                mAppsFile.failWrite(out);
            }
        } finally {
            IoUtils.closeQuietly(out);
        }
    }

    private void serializeApps(XmlSerializer serializer) throws IOException {
        serializer.startTag(null, TAG_LISTED_APPS);
        ArrayList<String> newAppsList = new ArrayList<>(mAppsList);
        for (String app : newAppsList) {
            serializer.startTag(null, TAG_APP);
            serializer.attribute(null, ATTRIBUTE_NAME, app);
            serializer.endTag(null, TAG_APP);
        }
        serializer.endTag(null, TAG_LISTED_APPS);
    }

    private void initDomainLists() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "initDomainLists(" + mUserId + ")");
        mDomainListsFile = new AtomicFile(getDomainListsFile());
        readDomainListsState();
    }

    private File getDomainListsFile() {
        File file = new File(Environment.getDataSystemCeDirectory(mUserId), DOMAIN_LISTS_FILE_NAME);
        if (DEBUG_FIREWALL) Slog.v(TAG, "getDomainListsFile(): " + file.getAbsolutePath());
        return file;
    }

    private void readDomainListsState() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "readDomainListsState()");
        mDomainListInfoList.clear();
        mPendingDomainListAdds.clear();
        try (FileInputStream in = mDomainListsFile.openRead()) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(in, null);
            parseDomainListsXml(parser);
            if (DEBUG_FIREWALL) Slog.v(TAG, "Read " + DOMAIN_LISTS_FILE_NAME + " successfully");
        } catch (FileNotFoundException e) {
            if (DEBUG_FIREWALL) Slog.v(TAG, DOMAIN_LISTS_FILE_NAME + " not found");
            Slog.i(TAG, DOMAIN_LISTS_FILE_NAME + " not found");
        } catch (XmlPullParserException | IOException e) {
            throw new IllegalStateException("Failed to parse " + DOMAIN_LISTS_FILE_NAME + ": " + mDomainListsFile, e);
        }
    }

    private void parseDomainListsXml(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        int type;
        int depth;
        int innerDepth = parser.getDepth() + 1;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                && ((depth = parser.getDepth()) >= innerDepth || type != XmlPullParser.END_TAG)) {
            if (depth > innerDepth || type != XmlPullParser.START_TAG) {
                continue;
            }
            if (parser.getName().equals(TAG_LISTED_DOMAIN_LISTS)) {
                parseDomainLists(parser);
                return;
            }
        }
        Slog.w(TAG, "Missing <" + TAG_LISTED_DOMAIN_LISTS + "> in " + DOMAIN_LISTS_FILE_NAME);
    }

    private void parseDomainLists(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        int type;
        int depth;
        int outerDepth = parser.getDepth() + 1;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                && ((depth = parser.getDepth()) >= outerDepth || type != XmlPullParser.END_TAG)) {
            if (depth > outerDepth || type != XmlPullParser.START_TAG) {
                continue;
            }
            if (parser.getName().equals(TAG_DOMAIN_LIST)) {
                DomainListInfo info = new DomainListInfo();
                info.id = parser.getAttributeValue(null, ATTRIBUTE_ID);
                info.title = parser.getAttributeValue(null, ATTRIBUTE_TITLE);
                info.url = parser.getAttributeValue(null, ATTRIBUTE_URL);
                String versionStr = parser.getAttributeValue(null, ATTRIBUTE_VERSION);
                try {
                    info.version = Double.parseDouble(versionStr);
                } catch (NumberFormatException e) {
                    info.version = 0.0;
                }
                info.isBlacklist = Boolean.parseBoolean(
                        parser.getAttributeValue(null, ATTRIBUTE_BLACKLIST));
                parseDomainListDomains(parser); // advance past domain children, not stored in memory
                mDomainListInfoList.add(info);
                if (DEBUG_FIREWALL) Slog.v(TAG, "parseDomainLists(): id=" + info.id);
            }
        }
    }

    private List<String> parseDomainListDomains(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        List<String> domains = new ArrayList<>();
        int type;
        int depth;
        int innerDepth = parser.getDepth() + 1;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                && ((depth = parser.getDepth()) >= innerDepth || type != XmlPullParser.END_TAG)) {
            if (depth > innerDepth || type != XmlPullParser.START_TAG) {
                continue;
            }
            if (parser.getName().equals(TAG_DOMAIN)) {
                String domainName = parser.getAttributeValue(null, ATTRIBUTE_NAME);
                domains.add(domainName);
            }
        }
        return domains;
    }

    private ArrayMap<String, List<String>> readDomainListDomainsFromFile() {
        ArrayMap<String, List<String>> result = new ArrayMap<>();
        if (mDomainListsFile == null) return result;
        try (FileInputStream in = mDomainListsFile.openRead()) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(in, null);
            int type;
            int depth;
            int innerDepth = parser.getDepth() + 1;
            while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                    && ((depth = parser.getDepth()) >= innerDepth || type != XmlPullParser.END_TAG)) {
                if (depth > innerDepth || type != XmlPullParser.START_TAG) continue;
                if (parser.getName().equals(TAG_LISTED_DOMAIN_LISTS)) {
                    int outerDepth = parser.getDepth() + 1;
                    while ((type = parser.next()) != XmlPullParser.END_DOCUMENT
                            && ((depth = parser.getDepth()) >= outerDepth || type != XmlPullParser.END_TAG)) {
                        if (depth > outerDepth || type != XmlPullParser.START_TAG) continue;
                        if (parser.getName().equals(TAG_DOMAIN_LIST)) {
                            String id = parser.getAttributeValue(null, ATTRIBUTE_ID);
                            List<String> domains = parseDomainListDomains(parser);
                            if (id != null) result.put(id, domains);
                        }
                    }
                    return result;
                }
            }
        } catch (FileNotFoundException e) {
            // no file yet
        } catch (XmlPullParserException | IOException e) {
            Slog.e(TAG, "Failed to read domain list domains from file", e);
        }
        return result;
    }

    private void writeDomainListsState() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "writeDomainListsState()");

        ArrayMap<String, List<String>> domains = readDomainListDomainsFromFile();
        domains.putAll(mPendingDomainListAdds);
        mPendingDomainListAdds.clear();

        FileOutputStream out = null;
        try {
            out = mDomainListsFile.startWrite();
            XmlSerializer serializer = Xml.newSerializer();
            serializer.setOutput(out, StandardCharsets.UTF_8.name());
            serializer.setFeature(
                    "http://xmlpull.org/v1/doc/features.html#indent-output", true);
            serializer.startDocument(null, true);
            serializeDomainLists(serializer, domains);
            serializer.endDocument();
            mDomainListsFile.finishWrite(out);
            if (DEBUG_FIREWALL) Slog.v(TAG, "Wrote " + DOMAIN_LISTS_FILE_NAME + " successfully");
        } catch (IllegalArgumentException | IllegalStateException | IOException e) {
            Slog.wtf(TAG, "Failed to write " + DOMAIN_LISTS_FILE_NAME + ", restoring backup", e);
            if (out != null) {
                mDomainListsFile.failWrite(out);
            }
        } finally {
            IoUtils.closeQuietly(out);
        }
    }

    private void serializeDomainLists(XmlSerializer serializer,
            ArrayMap<String, List<String>> domains) throws IOException {
        serializer.startTag(null, TAG_LISTED_DOMAIN_LISTS);
        for (DomainListInfo info : new ArrayList<>(mDomainListInfoList)) {
            serializer.startTag(null, TAG_DOMAIN_LIST);
            serializer.attribute(null, ATTRIBUTE_ID, info.id);
            serializer.attribute(null, ATTRIBUTE_TITLE, info.title);
            serializer.attribute(null, ATTRIBUTE_URL, info.url);
            serializer.attribute(null, ATTRIBUTE_VERSION, String.valueOf(info.version));
            serializer.attribute(null, ATTRIBUTE_BLACKLIST, String.valueOf(info.isBlacklist));
            List<String> list = domains.get(info.id);
            if (list != null) {
                for (String domain : list) {
                    serializer.startTag(null, TAG_DOMAIN);
                    serializer.attribute(null, ATTRIBUTE_NAME, domain);
                    serializer.endTag(null, TAG_DOMAIN);
                }
            }
            serializer.endTag(null, TAG_DOMAIN_LIST);
        }
        serializer.endTag(null, TAG_LISTED_DOMAIN_LISTS);
    }

    private void addDomainList(DomainListInfo info, List<String> domains) {
        if (DEBUG_FIREWALL) Slog.v(TAG, "addDomainList id:" + info.id);
        for (DomainListInfo existing : mDomainListInfoList) {
            if (existing.id.equals(info.id)) {
                if (DEBUG_FIREWALL) Slog.v(TAG, "addDomainList: id already exists, skipping");
                return;
            }
        }
        mDomainListInfoList.add(info);
        mPendingDomainListAdds.put(info.id, new ArrayList<>(domains));
        mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_DOMAIN_LISTS_STATE);
        mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
    }

    private void removeDomainList(String id) {
        if (DEBUG_FIREWALL) Slog.v(TAG, "removeDomainList id:" + id);
        DomainListInfo target = null;
        for (DomainListInfo info : mDomainListInfoList) {
            if (info.id.equals(id)) {
                target = info;
                break;
            }
        }
        if (target == null) {
            if (DEBUG_FIREWALL) Slog.v(TAG, "removeDomainList: id not found");
            return;
        }
        mPendingDomainListAdds.remove(id);
        mDomainListInfoList.remove(target);
        mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_DOMAIN_LISTS_STATE);
        mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
    }

    private List<DomainListInfo> getDomainLists() {
        return new ArrayList<>(mDomainListInfoList);
    }

    private void resetDnsConf() {
        ArrayList<String> confLines = new ArrayList<String>();
        boolean blacklist = isBlacklistMode();
        ArrayList<String> allDomains = new ArrayList<>(mManualDomainsList);
        if (!mDomainListInfoList.isEmpty()) {
            ArrayMap<String, List<String>> listDomains = readDomainListDomainsFromFile();
            for (DomainListInfo info : mDomainListInfoList) {
                if (info.isBlacklist == blacklist) {
                    List<String> domains = listDomains.get(info.id);
                    if (domains != null) allDomains.addAll(domains);
                }
            }
        }
        File dnsmasqDir = new File(Environment.getDataSystemCeDirectory(0), "dnsmasq");
        if (!dnsmasqDir.exists() && !dnsmasqDir.mkdirs())
            Slog.e(TAG, "Error while creating dnsmasq directory: " + dnsmasqDir);
        confLines.add("# Volla firewall fonfiguration file for dnsmasq.");
        if (!allDomains.isEmpty()) {
            for (String domain : allDomains) {
                if (blacklist) {
                    if (!isAllowed(domain))
                        confLines.add("address=/" + domain + "/127.0.0.1");
                } else {
                    confLines.add("server=/" + domain + "/" + COMMON_DNS);
                }
            }
            if (!blacklist) {
                // In whitelist mode, temporarily allowed domains need a server= line
                // so the catch-all address=/#/127.0.0.1 doesn't block them.
                for (int i = 0; i < mAllowedDomains.size(); i++) {
                    String allowed = mAllowedDomains.keyAt(i);
                    if (isAllowed(allowed) && !allDomains.contains(allowed))
                        confLines.add("server=/" + allowed + "/" + COMMON_DNS);
                }
                confLines.add("address=/#/127.0.0.1");
            }
        }
        // Always block known DoH providers so apps cannot bypass domain-level
        // blocking by switching to an encrypted resolver. Applied in all modes.
        for (String doh : KnownDohDomains.ALL) {
            confLines.add("address=/" + doh + "/127.0.0.1");
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

    private void resetRestrictedApps() {
        ArrayList<String> newAppsList = new ArrayList<>(mAppsList);
        for (String app : newAppsList) {
            ApplicationInfo aInfo;
            try {
                aInfo = mPackageManager.getApplicationInfo(app, 0);
                if (isActivate())
                    mPolicyManager.addUidPolicy(aInfo.uid, POLICY_REJECT_ALL);
                else
                    mPolicyManager.removeUidPolicy(aInfo.uid, POLICY_REJECT_ALL);
            } catch (PackageManager.NameNotFoundException e) {
                Slog.e(TAG, "Failed to find package " + app, e);
                removeAppFromList(app);
            }
        }
    }

    public void activate(boolean enable) {
        SystemProperties.set("persist.volla.firewall.enable", enable ? "true" : "false");
        SystemProperties.set("sys.volla.firewall.enable", enable ? "1" : "0");
        if (enable) {
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
            SystemProperties.set("ctl.start", "volla.dnsmasq");
        } else {
            SystemProperties.set("ctl.stop", "volla.dnsmasq");
        }
        mHandler.sendEmptyMessage(FirewallHandler.MSG_RESET_RESTRICTED_APPS);
        activateWebServer(enable);
        Settings.Global.putString(mContext.getContentResolver(), PRIVATE_DNS_DEFAULT_MODE,
            enable ? "off" : "opportunistic");
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
        if (!mManualDomainsList.contains(domain)) {
            mManualDomainsList.add(domain);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_STATE);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    private void removeDomainFromList(String domain) {
        if (mManualDomainsList.contains(domain)) {
            mManualDomainsList.remove(domain);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_STATE);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    public boolean isDomainOnList(String domain) {
        return mManualDomainsList.contains(domain);
    }

    private List<String> getDomainsList() {
        return mManualDomainsList;
    }

    private List<String> getManualDomains() {
        return mManualDomainsList;
    }

    private int getDomainsListCount() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "Number of domains on list: " + mManualDomainsList.size());
        return mManualDomainsList.size();
    }

    private void clearDomainList() {
        if (!mManualDomainsList.isEmpty()) {
            mManualDomainsList.clear();
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_STATE);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    private void addDomainListToList(List<String> domains) {
        if (!domains.isEmpty()) {
            mManualDomainsList.addAll(domains);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_STATE);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    private void addAppToList(String app) {
        if (DEBUG_FIREWALL) Slog.v(TAG, "addDomainToList app:" + app);
        if (!mAppsList.contains(app)) {
            mAppsList.add(app);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_APPS_STATE);
        }
    }

    private void removeAppFromList(String app) {
        if (mAppsList.contains(app)) {
            mAppsList.remove(app);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_APPS_STATE);
        }
    }

    public boolean isAppOnList(String app) {
        return mAppsList.contains(app);
    }

    private List<String> getAppsList() {
        return mAppsList;
    }

    private int getAppsListCount() {
        if (DEBUG_FIREWALL) Slog.v(TAG, "Number of apps on list: " + mAppsList.size());
        return mAppsList.size();
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
                .replace("DARKMODE_STATUS", String.valueOf(mUiModeMgr.isNightMode(Display.DEFAULT_DISPLAY)));
    }

    // ── Alert mode ────────────────────────────────────────────────────────

    private void setAlertMode(boolean enable) {
        SystemProperties.set(PROP_ALERT_MODE, Boolean.toString(enable));
    }

    private boolean isAlertMode() {
        return SystemProperties.getBoolean(PROP_ALERT_MODE, false);
    }

    // ── Allowed list ──────────────────────────────────────────────────────

    private void initAllowedDomains() {
        mAllowedDomains.clear();
        if (mAllowedFile == null) return;
        try (FileInputStream fis = mAllowedFile.openRead()) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(fis, StandardCharsets.UTF_8.name());
            int type;
            while ((type = parser.next()) != XmlPullParser.END_DOCUMENT) {
                if (type == XmlPullParser.START_TAG && TAG_ALLOWED_DOMAIN.equals(parser.getName())) {
                    String name = parser.getAttributeValue(null, ATTRIBUTE_NAME);
                    long expiry = Long.parseLong(parser.getAttributeValue(null, ATTRIBUTE_EXPIRY));
                    if (name != null && (expiry == -1 || System.currentTimeMillis() < expiry))
                        mAllowedDomains.put(name, expiry);
                }
            }
        } catch (FileNotFoundException ignored) {
        } catch (Exception e) {
            Slog.e(TAG, "Failed to read allowed list", e);
        }
        Slog.i(TAG, "initAllowedDomains: loaded " + mAllowedDomains.size() + " entries");
    }

    private void writeAllowedDomains() {
        if (mAllowedFile == null) return;
        FileOutputStream fos = null;
        try {
            fos = mAllowedFile.startWrite();
            XmlSerializer out = Xml.newSerializer();
            out.setOutput(fos, StandardCharsets.UTF_8.name());
            out.startDocument(null, true);
            out.startTag(null, TAG_ALLOWED_DOMAINS);
            for (int i = 0; i < mAllowedDomains.size(); i++) {
                out.startTag(null, TAG_ALLOWED_DOMAIN);
                out.attribute(null, ATTRIBUTE_NAME, mAllowedDomains.keyAt(i));
                out.attribute(null, ATTRIBUTE_EXPIRY, Long.toString(mAllowedDomains.valueAt(i)));
                out.endTag(null, TAG_ALLOWED_DOMAIN);
            }
            out.endTag(null, TAG_ALLOWED_DOMAINS);
            out.endDocument();
            mAllowedFile.finishWrite(fos);
        } catch (Exception e) {
            mAllowedFile.failWrite(fos);
            Slog.e(TAG, "Failed to write allowed list", e);
        }
    }

    private boolean isAllowed(String domain) {
        Long expiry = mAllowedDomains.get(domain);
        if (expiry == null) return false;
        return expiry == -1 || System.currentTimeMillis() < expiry;
    }

    private List<lineageos.firewall.AllowedDomain> getAllowedDomainsList() {
        List<lineageos.firewall.AllowedDomain> result = new ArrayList<>();
        for (int i = 0; i < mAllowedDomains.size(); i++) {
            result.add(new lineageos.firewall.AllowedDomain(
                mAllowedDomains.keyAt(i), mAllowedDomains.valueAt(i)));
        }
        return result;
    }

    private void removeAllowedDomain(String name) {
        if (mAllowedDomains.remove(name) != null) {
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_ALLOWED);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    // Use a method reference so the lambda body (field initializer) does not directly
    // reference mHandler — a blank-final field only assigned in the constructor.
    // mHandler is accessed inside checkExpiredAllowedDomains() at call time, which is safe.
    private final Runnable mExpireRunnable = this::checkExpiredAllowedDomains;

    private void checkExpiredAllowedDomains() {
        long now = System.currentTimeMillis();
        boolean changed = false;
        for (int i = mAllowedDomains.size() - 1; i >= 0; i--) {
            long exp = mAllowedDomains.valueAt(i);
            if (exp != -1 && now >= exp) {
                mAllowedDomains.removeAt(i);
                changed = true;
            }
        }
        if (changed) {
            writeAllowedDomains();
            mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
        }
    }

    // ── Notifications ─────────────────────────────────────────────────────

    private void setupNotificationChannel() {
        NotificationManager nm = mContext.getSystemService(NotificationManager.class);
        if (nm == null) return;
        NotificationChannel ch = new NotificationChannel(
            NOTIF_CHANNEL_ID,
            mContext.getString(org.lineageos.platform.internal.R.string.firewall_notif_channel_name),
            NotificationManager.IMPORTANCE_HIGH);
        ch.setDescription(mContext.getString(
            org.lineageos.platform.internal.R.string.firewall_notif_channel_desc));
        nm.createNotificationChannel(ch);
    }

    private void registerNotifActionReceiver() {
        if (mNotifActionReceiver != null) return;
        mNotifActionReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String action = intent.getAction();
                String domain = intent.getStringExtra(EXTRA_DOMAIN);
                int notifId = intent.getIntExtra(EXTRA_NOTIF_ID, 0);
                if (domain == null || action == null) return;

                NotificationManager nm = mContext.getSystemService(NotificationManager.class);
                if (nm != null) nm.cancel(notifId);

                if (ACTION_ALLOW_TEMP.equals(action)) {
                    long expiry = System.currentTimeMillis() + ALLOW_TEMP_MS;
                    mAllowedDomains.put(domain, expiry);
                    writeAllowedDomains();
                    mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
                    mHandler.removeCallbacks(mExpireRunnable);
                    mHandler.postDelayed(mExpireRunnable, ALLOW_TEMP_MS + 1000);
                    if (mBlockDb != null) mBlockDb.updateAllowed(domain, "temp");
                } else if (ACTION_ALLOW_PERM.equals(action)) {
                    mAllowedDomains.put(domain, -1L);
                    writeAllowedDomains();
                    mHandler.sendEmptyMessage(FirewallHandler.MSG_WRITE_CONF);
                    if (mBlockDb != null) mBlockDb.updateAllowed(domain, "perm");
                }
                // ACTION_DENY: notification already cancelled above, nothing else to do
            }
        };
        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_DENY);
        filter.addAction(ACTION_ALLOW_TEMP);
        filter.addAction(ACTION_ALLOW_PERM);
        mContext.registerReceiver(mNotifActionReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
    }

    void onDomainBlocked(String domain, int uid, String pkg, String appName, int port) {
        // Determine domain source: manual list (in RAM) or a template (file lookup).
        String sourceType, templateName;
        if (mManualDomainsList.contains(domain)) {
            sourceType = "manual";
            templateName = null;
        } else {
            sourceType = "template";
            templateName = null;
            ArrayMap<String, List<String>> listDomains = readDomainListDomainsFromFile();
            outer:
            for (DomainListInfo info : mDomainListInfoList) {
                List<String> domains = listDomains.get(info.id);
                if (domains != null && domains.contains(domain)) {
                    templateName = info.title;
                    break outer;
                }
            }
        }

        if (mBlockDb != null) {
            mBlockDb.insertEvent(System.currentTimeMillis(), domain, appName, pkg,
                port == 443, isBlacklistMode(), sourceType, templateName);
        }

        if (!isAlertMode()) return;
        int notifId = domain.hashCode();

        // Set package="android" to make the intent explicit — bypasses the
        // AOSP protected-broadcast check for uid=1000 sending implicit broadcasts.
        Intent denyIntent = new Intent(ACTION_DENY).setPackage(PKG_SYSTEM)
            .putExtra(EXTRA_DOMAIN, domain).putExtra(EXTRA_NOTIF_ID, notifId);
        Intent allowTmpIntent = new Intent(ACTION_ALLOW_TEMP).setPackage(PKG_SYSTEM)
            .putExtra(EXTRA_DOMAIN, domain).putExtra(EXTRA_PKG, pkg)
            .putExtra(EXTRA_NOTIF_ID, notifId);
        Intent allowPermIntent = new Intent(ACTION_ALLOW_PERM).setPackage(PKG_SYSTEM)
            .putExtra(EXTRA_DOMAIN, domain).putExtra(EXTRA_PKG, pkg)
            .putExtra(EXTRA_NOTIF_ID, notifId);

        int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
        PendingIntent denyPi     = PendingIntent.getBroadcast(mContext, notifId,     denyIntent,     flags);
        PendingIntent allowTmpPi = PendingIntent.getBroadcast(mContext, notifId + 1, allowTmpIntent, flags);
        PendingIntent allowPermPi = PendingIntent.getBroadcast(mContext, notifId + 2, allowPermIntent, flags);

        Notification.Builder builder = new Notification.Builder(mContext, NOTIF_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(mContext.getString(
                org.lineageos.platform.internal.R.string.firewall_notif_title))
            .setContentText(mContext.getString(
                org.lineageos.platform.internal.R.string.firewall_notif_text, appName, domain))
            .setAutoCancel(true)
            .setTimeoutAfter(10_000)
            .setVibrate(new long[]{0, 300, 100, 300})
            .addAction(new Notification.Action.Builder(null, mContext.getString(
                org.lineageos.platform.internal.R.string.firewall_notif_action_deny), denyPi).build())
            .addAction(new Notification.Action.Builder(null, mContext.getString(
                org.lineageos.platform.internal.R.string.firewall_notif_action_allow_temp), allowTmpPi).build())
            .addAction(new Notification.Action.Builder(null, mContext.getString(
                org.lineageos.platform.internal.R.string.firewall_notif_action_allow_perm), allowPermPi).build());

        if (pkg != null) {
            try {
                Drawable d = mPackageManager.getApplicationIcon(pkg);
                Bitmap icon = drawableToBitmap(d);
                builder.setLargeIcon(icon);
            } catch (Exception ignored) {}
        }

        NotificationManager nm = mContext.getSystemService(NotificationManager.class);
        if (nm != null) {
            nm.cancel(notifId);
            nm.notify(notifId, builder.build());
        }
    }

    private static Bitmap drawableToBitmap(Drawable drawable) {
        if (drawable instanceof android.graphics.drawable.BitmapDrawable) {
            Bitmap bm = ((android.graphics.drawable.BitmapDrawable) drawable).getBitmap();
            if (bm != null) return bm;
        }
        int w = Math.max(drawable.getIntrinsicWidth(), 1);
        int h = Math.max(drawable.getIntrinsicHeight(), 1);
        Bitmap bm = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bm);
        drawable.setBounds(0, 0, w, h);
        drawable.draw(canvas);
        return bm;
    }

    private final IBinder mService = new IFirewallService.Stub() {
        @Override
        public void activate(boolean enable) {
            long token = clearCallingIdentity();
            FirewallService.this.activate(enable);
            restoreCallingIdentity(token);
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

        @Override
        public void addDomainListToList(List<String> domains) {
            FirewallService.this.addDomainListToList(domains);
        }

        @Override
        public List<String> getManualDomains() {
            return FirewallService.this.getManualDomains();
        }

        @Override
        public void addDomainList(lineageos.firewall.DomainListInfo info, List<String> domains) {
            FirewallService.this.addDomainList(info, domains);
        }

        @Override
        public void removeDomainList(String id) {
            FirewallService.this.removeDomainList(id);
        }

        @Override
        public List<lineageos.firewall.DomainListInfo> getDomainLists() {
            return FirewallService.this.getDomainLists();
        }

        @Override
        public void addAppToList(String app) {
            FirewallService.this.addAppToList(app);
        }

        @Override
        public void removeAppFromList(String app) {
            FirewallService.this.removeAppFromList(app);
        }

        @Override
        public boolean isAppOnList(String app) {
            return FirewallService.this.isAppOnList(app);
        }

        @Override
        public int getAppsListCount() {
            return FirewallService.this.getAppsListCount();
        }

        @Override
        public List<String> getAppsList() {
            return FirewallService.this.getAppsList();
        }

        @Override
        public void alertMode(boolean enable) {
            FirewallService.this.setAlertMode(enable);
        }

        @Override
        public boolean isAlertMode() {
            return FirewallService.this.isAlertMode();
        }

        @Override
        public List<lineageos.firewall.AllowedDomain> getAllowedDomains() {
            return FirewallService.this.getAllowedDomainsList();
        }

        @Override
        public void removeAllowedDomain(String name) {
            FirewallService.this.removeAllowedDomain(name);
        }

        @Override
        public ParcelFileDescriptor getBlockEventsDb() {
            if (mBlockDb == null) return null;
            try {
                mBlockDb.checkpoint();
                final File dbFile = new File(Environment.getDataSystemCeDirectory(mUserId),
                    "firewall_events.db");
                // Return a pipe so the client can read the raw bytes and save them
                // to its own cache dir. A direct PFD to the file would have SQLite
                // resolve the /proc/self/fd symlink back to the protected real path,
                // causing SQLITE_CANTOPEN (Permission denied).
                final ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
                new Thread(() -> {
                    try (ParcelFileDescriptor.AutoCloseOutputStream out =
                                new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]);
                         java.io.FileInputStream in = new java.io.FileInputStream(dbFile)) {
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                    } catch (Exception e) {
                        Slog.e(TAG, "getBlockEventsDb pipe write failed", e);
                        IoUtils.closeQuietly(pipe[1]);
                    }
                }, "firewall-db-pipe").start();
                return pipe[0];
            } catch (Exception e) {
                Slog.e(TAG, "getBlockEventsDb failed", e);
                return null;
            }
        }

        @Override
        public void clearBlockEvents() {
            if (mBlockDb != null) mBlockDb.clearEvents();
        }
    };

    private class FirewallHandler extends Handler {

        public static final int MSG_INIT_DOMAINS = 0;
        public static final int MSG_WRITE_STATE = 1;
        public static final int MSG_WRITE_CONF = 2;
        public static final int MSG_INIT_APPS = 3;
        public static final int MSG_WRITE_APPS_STATE = 4;
        public static final int MSG_RESET_RESTRICTED_APPS = 5;
        public static final int MSG_INIT_DOMAIN_LISTS = 6;
        public static final int MSG_WRITE_DOMAIN_LISTS_STATE = 7;
        public static final int MSG_INIT_ALLOWED = 8;
        public static final int MSG_WRITE_ALLOWED = 9;

        public FirewallHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(android.os.Message msg) {
            switch (msg.what) {
                case MSG_INIT_DOMAINS:
                    initLockedDomains();
                    break;
                case MSG_WRITE_STATE:
                    writeDomainsState();
                    break;
                case MSG_WRITE_CONF:
                    resetDnsConf();
                    break;
                case MSG_INIT_APPS:
                    initRestrictedApps();
                    break;
                case MSG_WRITE_APPS_STATE:
                    writeAppsState();
                    break;
                case MSG_RESET_RESTRICTED_APPS:
                    resetRestrictedApps();
                    break;
                case MSG_INIT_DOMAIN_LISTS:
                    initDomainLists();
                    break;
                case MSG_WRITE_DOMAIN_LISTS_STATE:
                    writeDomainListsState();
                    break;
                case MSG_INIT_ALLOWED:
                    initAllowedDomains();
                    break;
                case MSG_WRITE_ALLOWED:
                    writeAllowedDomains();
                    break;
                default:
                    Slog.w(TAG, "Unknown message:" + msg.what);
            }
        }
    }

    private class SNIKeyManager extends X509ExtendedKeyManager {
        private String extractSNI(SSLSession session) {
            if (session instanceof ExtendedSSLSession) {
                List<SNIServerName> names =
                    ((ExtendedSSLSession) session).getRequestedServerNames();
                if (names != null && !names.isEmpty()) {
                    String sni = new String(names.get(0).getEncoded(), StandardCharsets.US_ASCII);
                    if (DEBUG_FIREWALL) Slog.v(TAG, "SNIKeyManager: SNI=" + sni);
                    return sni;
                }
            }
            return null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType,
                java.security.Principal[] issuers, javax.net.ssl.SSLEngine engine) {
            // Prefer the SNI pre-parsed from the raw ClientHello bytes (set by TcpProxy
            // via ThreadLocal). Conscrypt's getRequestedServerNames() is unreliable in the
            // bridge setup and may return null even when the ClientHello contains SNI.
            String sni = TcpProxy.sBridgeSni.get();
            if (sni != null) return sni;
            sni = extractSNI(engine.getHandshakeSession());
            return sni != null ? sni : "blocked.local";
        }

        @Override
        public String chooseServerAlias(String keyType, java.security.Principal[] issuers,
                java.net.Socket socket) {
            String sni = TcpProxy.sBridgeSni.get();
            if (sni != null) return sni;
            if (socket instanceof SSLSocket) {
                sni = extractSNI(((SSLSocket) socket).getHandshakeSession());
                if (sni != null) return sni;
            }
            return "blocked.local";
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            LeafCertEntry entry = generateLeafCert(alias);
            if (entry == null || mCACert == null) return null;
            return new X509Certificate[]{entry.cert, mCACert};
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            LeafCertEntry entry = generateLeafCert(alias);
            return entry != null ? entry.key : null;
        }

        @Override
        public String[] getClientAliases(String kt, java.security.Principal[] i) { return null; }
        @Override
        public String[] getServerAliases(String kt, java.security.Principal[] i) { return null; }
        @Override
        public String chooseClientAlias(String[] kt, java.security.Principal[] i,
                java.net.Socket s) { return null; }
    }


}
