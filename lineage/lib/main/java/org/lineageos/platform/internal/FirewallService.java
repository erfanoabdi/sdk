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
import java.util.Set;

import libcore.io.IoUtils;
import lineageos.app.LineageContextConstants;
import lineageos.firewall.IFirewallService;

import static android.provider.Settings.Global.PRIVATE_DNS_DEFAULT_MODE;

import fi.iki.elonen.NanoHTTPD;

public class FirewallService extends LineageSystemService {

    private static final String TAG = "FirewallService";
    private static final boolean DEBUG_FIREWALL = true;

    private static final String DOMAINS_FILE_NAME = "list-domains.xml";
    private static final String TAG_LISTED_DOMAINS = "list-domains";
    private static final String TAG_DOMAIN = "domain";
    private static final String APPS_FILE_NAME = "list-restrictedapps.xml";
    private static final String TAG_LISTED_APPS = "list-restrictedapps";
    private static final String TAG_APP = "app";
    private static final String ATTRIBUTE_NAME = "name";
    private static final String COMMON_DNS = "1.1.1.1";

    private int mUserId;
    private Context mContext;
    private UiModeManagerInternal mUiModeMgr;
    private PackageManager mPackageManager;
    private NetworkPolicyManager mPolicyManager;

    private AtomicFile mDomainsFile;
    private AtomicFile mAppsFile;
    private final FirewallHandler mHandler;

    private HttpWebServer mHttpWebServer;
    private HttpsWebServer mHttpsWebServer;
    private boolean isWebServerEnabled;

    private final ArrayList<String> mDomainsList = new ArrayList<String>();
    private final ArrayList<String> mAppsList = new ArrayList<String>();

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
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_DOMAINS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_APPS);
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

            if (isActivate()) {
                SystemProperties.set("ctl.start", "volla.dnsmasq");
                activateWebServer(true);
            }
        }
    }

    @Override
    public void onUserSwitching(@Nullable TargetUser from, @NonNull TargetUser to) {
        int userHandle = to.getUserIdentifier();
        if (DEBUG_FIREWALL) Slog.v(TAG, "onSwitchUser() mUserId:" + userHandle);
        if (!UserManager.get(mContext).isManagedProfile(userHandle)) {
            if (DEBUG_FIREWALL) Slog.v(TAG, "onSwitchUser() is NOT ManagedProfile");
            mUserId = userHandle;
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_DOMAINS);
            mHandler.sendEmptyMessage(FirewallHandler.MSG_INIT_APPS);
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
        mDomainsList.clear();
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
                mDomainsList.add(domainName);
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
        for (String domain : mDomainsList) {
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
        for (String app : mAppsList) {
            serializer.startTag(null, TAG_APP);
            serializer.attribute(null, ATTRIBUTE_NAME, app);
            serializer.endTag(null, TAG_APP);
        }
        serializer.endTag(null, TAG_LISTED_APPS);
    }

    private void resetDnsConf() {
        ArrayList<String> confLines = new ArrayList<String>();
        boolean blacklist = isBlacklistMode();
        File dnsmasqDir = new File(Environment.getDataSystemCeDirectory(0), "dnsmasq");
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

    private void resetRestrictedApps() {
        for (String app : mAppsList) {
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

    private void addDomainListToList(List<String> domains) {
        if (!domains.isEmpty()) {
            mDomainsList.addAll(domains);
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
                .replace("DARKMODE_STATUS", String.valueOf(mUiModeMgr.isNightMode()));
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
    };

    private class FirewallHandler extends Handler {

        public static final int MSG_INIT_DOMAINS = 0;
        public static final int MSG_WRITE_STATE = 1;
        public static final int MSG_WRITE_CONF = 2;
        public static final int MSG_INIT_APPS = 3;
        public static final int MSG_WRITE_APPS_STATE = 4;
        public static final int MSG_RESET_RESTRICTED_APPS = 5;

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
