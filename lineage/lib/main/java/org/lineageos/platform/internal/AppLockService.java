/**
 * Copyright (C) 2017-2020 Paranoid Android
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
import android.os.SystemProperties;
import android.os.UserManager;
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import libcore.io.IoUtils;
import lineageos.app.LineageContextConstants;
import lineageos.applock.IAppLockCallback;
import lineageos.applock.IAppLockService;

public class AppLockService extends LineageSystemService {

    private static final String TAG = "AppLockService";
    private static final boolean DEBUG_APPLOCK = true;

    private static final String FILE_NAME = "locked-apps.xml";
    private static final String TAG_LOCKED_APPS = "locked-apps";
    private static final String TAG_PACKAGE = "package";
    private static final String ATTRIBUTE_NAME = "name";

    private PackageManager mPackageManager;

    private int mUserId;
    private Context mContext;

    private AtomicFile mFile;
    private final AppLockHandler mHandler;

    private final ArrayMap<String, AppLockContainer> mAppsList = new ArrayMap<>();
    private final ArraySet<IAppLockCallback> mCallbacks = new ArraySet<>();

    private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())
                    && !intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
                if (DEBUG_APPLOCK) Slog.v(TAG, "Package removed intent received");
                final Uri data = intent.getData();
                if (data == null) {
                    if (DEBUG_APPLOCK) Slog.v(TAG,
                            "Cannot handle package broadcast with null data");
                    return;
                }

                final String packageName = data.getSchemeSpecificPart();
                removeAppFromList(packageName);
            }
        }
    };

    public AppLockService(Context context) {
        super(context);

        mContext = context;
        mHandler = new AppLockHandler(BackgroundThread.getHandler().getLooper());
        mUserId = ActivityManager.getCurrentUser();

        IntentFilter packageFilter = new IntentFilter();
        packageFilter.addAction(Intent.ACTION_PACKAGE_REMOVED);
        packageFilter.addDataScheme("package");
        context.registerReceiver(mReceiver, packageFilter);
    }

    @Override
    public String getFeatureDeclaration() {
        return LineageContextConstants.Features.HARDWARE_ABSTRACTION;
    }

    @Override
    public void onStart() {
        if (DEBUG_APPLOCK) Slog.v(TAG, "Starting AppLockService");
        publishBinderService(LineageContextConstants.VOLLA_APPLOCK_SERVICE, mService);
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == SystemService.PHASE_SYSTEM_SERVICES_READY) {
            Slog.v(TAG, "onBootPhase PHASE_SYSTEM_SERVICES_READY");
            mPackageManager = mContext.getPackageManager();
        }
    }

    @Override
    public void onUnlockUser(int userHandle) {
        if (DEBUG_APPLOCK) Slog.v(TAG, "onUnlockUser() mUserId:" + userHandle);
        if (!UserManager.get(mContext).isManagedProfile(userHandle)) {
            if (DEBUG_APPLOCK) Slog.v(TAG, "onUnlockUser() is NOT ManagedProfile");
            mUserId = userHandle;
            mHandler.sendEmptyMessage(AppLockHandler.MSG_INIT_APPS);
        }
    }

    @Override
    public void onSwitchUser(int userHandle) {
        if (DEBUG_APPLOCK) Slog.v(TAG, "onSwitchUser() mUserId:" + userHandle);
        if (!UserManager.get(mContext).isManagedProfile(userHandle)) {
            if (DEBUG_APPLOCK) Slog.v(TAG, "onSwitchUser() is NOT ManagedProfile");
            mUserId = userHandle;
            mHandler.sendEmptyMessage(AppLockHandler.MSG_INIT_APPS);
        }
    }

    @Override
    public void onStopUser(int userHandle) {
        if (DEBUG_APPLOCK) Slog.v(TAG, "onStopUser() userHandle:" + userHandle);
        if (mUserId == userHandle) {
            mUserId = ActivityManager.getCurrentUser();
            mHandler.sendEmptyMessage(AppLockHandler.MSG_INIT_APPS);
        }
    }

    private void initLockedApps() {
        if (DEBUG_APPLOCK) Slog.v(TAG, "initLockedApps(" + mUserId + ")");
        mFile = new AtomicFile(getFile());
        readState();
    }

    private File getFile() {
        File file = new File(Environment.getDataSystemCeDirectory(mUserId), FILE_NAME);
        if (DEBUG_APPLOCK) Slog.v(TAG, "getFile(): " + file.getAbsolutePath());
        return file;
    }

    private void readState() {
        if (DEBUG_APPLOCK) Slog.v(TAG, "readState()");
        mAppsList.clear();
        try (FileInputStream in = mFile.openRead()) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(in, null);
            parseXml(parser);
            if (DEBUG_APPLOCK) Slog.v(TAG, "Read locked-apps.xml successfully");
        } catch (FileNotFoundException e) {
            if (DEBUG_APPLOCK) Slog.v(TAG, "locked-apps.xml not found");
            Slog.i(TAG, "locked-apps.xml not found");
        } catch (XmlPullParserException | IOException e) {
            throw new IllegalStateException("Failed to parse locked-apps.xml: " + mFile, e);
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
            if (parser.getName().equals(TAG_LOCKED_APPS)) {
                parsePackages(parser);
                return;
            }
        }
        Slog.w(TAG, "Missing <" + TAG_LOCKED_APPS + "> in locked-apps.xml");
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
            if (parser.getName().equals(TAG_PACKAGE)) {
                String pkgName = parser.getAttributeValue(null, ATTRIBUTE_NAME);
                AppLockContainer cont = new AppLockContainer(pkgName);
                mAppsList.put(pkgName, cont);
                if (DEBUG_APPLOCK) Slog.v(TAG, "parsePackages(): pkgName=" + pkgName);
            }
        }
    }

    private void writeState() {
        if (DEBUG_APPLOCK) Slog.v(TAG, "writeState()");

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
            if (DEBUG_APPLOCK) Slog.v(TAG, "Wrote locked-apps.xml successfully");
        } catch (IllegalArgumentException | IllegalStateException | IOException e) {
            Slog.wtf(TAG, "Failed to write locked-apps.xml, restoring backup", e);
            if (out != null) {
                mFile.failWrite(out);
            }
        } finally {
            IoUtils.closeQuietly(out);
        }
    }

    private void serializeLockedApps(XmlSerializer serializer) throws IOException {
        serializer.startTag(null, TAG_LOCKED_APPS);
        ArrayList<AppLockContainer> apps = new ArrayList<>(mAppsList.values());
        for (AppLockContainer app : apps) {
            serializer.startTag(null, TAG_PACKAGE);
            serializer.attribute(null, ATTRIBUTE_NAME, app.packageName);
            serializer.endTag(null, TAG_PACKAGE);
        }
        serializer.endTag(null, TAG_LOCKED_APPS);
    }

    public void activate(boolean enable) {
        ArrayList<AppLockContainer> apps = new ArrayList<>(mAppsList.values());
        for (AppLockContainer app : apps) {
            mPackageManager.setApplicationEnabledSetting(app.packageName, enable ?
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED :
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED, 0);
        }
        SystemProperties.set("persist.volla.applock.enable", enable ? "true" : "false");
    }

    public boolean isActivate() {
        return SystemProperties.getBoolean("persist.volla.applock.enable", false);
    }

    public void enableInstallLocker(boolean enable) {
        SystemProperties.set("persist.volla.unknown_app.block", enable ? "true" : "false");
    }

    public boolean isInstallLockerEnabled() {
        return SystemProperties.getBoolean("persist.volla.unknown_app.block", false);
    }

    private void addAppToList(String packageName) {
        if (DEBUG_APPLOCK) Slog.v(TAG, "addAppToList packageName:" + packageName);
        try {
            mPackageManager.getApplicationInfo(packageName, 0);
            if (!mAppsList.containsKey(packageName)) {
                AppLockContainer cont = new AppLockContainer(packageName);
                cont.appAddedToList();
                mAppsList.put(packageName, cont);
                mHandler.sendEmptyMessage(AppLockHandler.MSG_WRITE_STATE);
                dispatchCallbacks(packageName);
            }
        } catch(PackageManager.NameNotFoundException e) {
            Slog.e(TAG, "Failed to find package " + packageName, e);
        }
    }

    private void removeAppFromList(String packageName) {
        if (mAppsList.containsKey(packageName)) {
            AppLockContainer cont = getAppLockContainer(packageName);
            cont.appRemovedFromList();
            mAppsList.remove(packageName);
            mHandler.sendEmptyMessage(AppLockHandler.MSG_WRITE_STATE);
            dispatchCallbacks(packageName);
        }
    }

    public boolean isAppLocked(String packageName) {
        return mAppsList.containsKey(packageName);
    }

    private AppLockContainer getAppLockContainer(String packageName) {
        return mAppsList.get(packageName);
    }

    private List<String> getLockedPackages() {
        return new ArrayList<String>(mAppsList.keySet());
    }

    private int getLockedAppsCount() {
        if (DEBUG_APPLOCK) Slog.v(TAG, "Number of locked apps: " + mAppsList.size());
        return mAppsList.size();
    }

    private void dispatchCallbacks(String packageName) {
        mHandler.post(() -> {
            synchronized (mCallbacks) {
                final int N = mCallbacks.size();
                boolean cleanup = false;
                for (int i = 0; i < N; i++) {
                    final IAppLockCallback callback = mCallbacks.valueAt(i);
                    try {
                        if (callback != null) {
                            callback.onAppStateChanged(packageName);
                        } else {
                            cleanup = true;
                        }
                    } catch (RemoteException e) {
                        cleanup = true;
                    }
                }
                if (cleanup) {
                    cleanUpCallbacksLocked(null);
                }
            }
        });
    }

    private void cleanUpCallbacksLocked(IAppLockCallback callback) {
        mHandler.post(() -> {
            synchronized (mCallbacks) {
                for (int i = mCallbacks.size() - 1; i >= 0; i--) {
                    IAppLockCallback found = mCallbacks.valueAt(i);
                    if (found == null || found == callback) {
                        mCallbacks.remove(i);
                    }
                }
            }
        });
    }

    private void addAppLockCallback(IAppLockCallback callback) {
        mHandler.post(() -> {
            synchronized(mCallbacks) {
                if (!mCallbacks.contains(callback)) {
                    mCallbacks.add(callback);
                }
            }
        });
    }

    private void removeAppLockCallback(IAppLockCallback callback) {
        mHandler.post(() -> {
            synchronized(mCallbacks) {
                if (mCallbacks.contains(callback)) {
                    mCallbacks.remove(callback);
                }
            }
        });
    }

    private final IBinder mService = new IAppLockService.Stub() {
        @Override
        public void activate(boolean enable) {
            AppLockService.this.activate(enable);
        }

        @Override
        public boolean isActivate() {
            return AppLockService.this.isActivate();
        }

        @Override
        public void enableInstallLocker(boolean enable) {
            AppLockService.this.enableInstallLocker(enable);
        }

        @Override
        public boolean isInstallLockerEnabled() {
            return AppLockService.this.isInstallLockerEnabled();
        }

        @Override
        public void addAppToList(String packageName) {
            AppLockService.this.addAppToList(packageName);
        }

        @Override
        public void removeAppFromList(String packageName) {
            AppLockService.this.removeAppFromList(packageName);
        }

        @Override
        public boolean isAppLocked(String packageName) {
            return AppLockService.this.isAppLocked(packageName);
        }

        @Override
        public int getLockedAppsCount() {
            return AppLockService.this.getLockedAppsCount();
        }

        @Override
        public List<String> getLockedPackages() {
            return AppLockService.this.getLockedPackages();
        }

        @Override
        public void addAppLockCallback(IAppLockCallback callback) {
            AppLockService.this.addAppLockCallback(callback);
        }

        @Override
        public void removeAppLockCallback(IAppLockCallback callback) {
            AppLockService.this.removeAppLockCallback(callback);
        }
    };

    private class AppLockHandler extends Handler {

        public static final int MSG_INIT_APPS = 0;
        public static final int MSG_READ_STATE = 1;
        public static final int MSG_WRITE_STATE = 2;

        public AppLockHandler(Looper looper) {
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
                default:
                    Slog.w(TAG, "Unknown message:" + msg.what);
            }
        }
    }

    private class AppLockContainer {
        private final String packageName;
        private ApplicationInfo aInfo;
        private CharSequence appLabel;

        public AppLockContainer(String pkg) {
            packageName = pkg;

            try {
                aInfo = mPackageManager.getApplicationInfo(packageName, 0);
            } catch(PackageManager.NameNotFoundException e) {
                Slog.e(TAG, "Failed to find package " + packageName, e);
                removeAppFromList(packageName);
                return;
            }
            appLabel = mPackageManager.getApplicationLabel(aInfo);
        }

        private void appRemovedFromList() {
            if (isActivate())
                mPackageManager.setApplicationEnabledSetting(packageName, PackageManager.COMPONENT_ENABLED_STATE_ENABLED, 0);
        }

        private void appAddedToList() {
            if (isActivate())
                mPackageManager.setApplicationEnabledSetting(packageName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, 0);
        }
    }
}
