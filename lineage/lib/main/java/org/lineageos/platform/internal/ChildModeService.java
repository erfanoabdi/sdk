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
import android.content.Context;
import android.os.Environment;
import android.os.SystemProperties;
import android.os.IBinder;
import android.os.UserHandle;
import android.os.UserManager;
import android.util.Slog;

import lineageos.childmode.IChildModeService;
import lineageos.applock.AppLockManager;
import lineageos.firewall.FirewallManager;
import lineageos.app.LineageContextConstants;

import com.android.internal.R;
import com.android.server.LocalServices;
import com.android.server.SystemService;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class ChildModeService extends LineageSystemService {

    private static final String TAG = "ChildModeService";
    private static final boolean DEBUG_CHILDMODE = true;

    private int mUserId;
    private Context mContext;
    private MessageDigest mDigest;

    public ChildModeService(Context context) {
        super(context);
        mContext = context;
        mUserId = ActivityManager.getCurrentUser();
        try {
            mDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getFeatureDeclaration() {
        return LineageContextConstants.Features.HARDWARE_ABSTRACTION;
    }

    @Override
    public void onStart() {
        if (DEBUG_CHILDMODE) Slog.v(TAG, "Starting ChildModeService");
        publishBinderService(LineageContextConstants.VOLLA_CHILDMODE_SERVICE, mService);
    }

    @Override
    public void onUnlockUser(int userHandle) {
        if (DEBUG_CHILDMODE) Slog.v(TAG, "onUnlockUser() mUserId:" + userHandle);
        if (!UserManager.get(mContext).isManagedProfile(userHandle)) {
            if (DEBUG_CHILDMODE) Slog.v(TAG, "onUnlockUser() is NOT ManagedProfile");
            mUserId = userHandle;
        }
    }

    @Override
    public void onSwitchUser(int userHandle) {
        if (DEBUG_CHILDMODE) Slog.v(TAG, "onSwitchUser() mUserId:" + userHandle);
        if (!UserManager.get(mContext).isManagedProfile(userHandle)) {
            if (DEBUG_CHILDMODE) Slog.v(TAG, "onSwitchUser() is NOT ManagedProfile");
            mUserId = userHandle;
        }
    }

    @Override
    public void onStopUser(int userHandle) {
        if (DEBUG_CHILDMODE) Slog.v(TAG, "onStopUser() userHandle:" + userHandle);
        if (mUserId == userHandle) {
            mUserId = ActivityManager.getCurrentUser();
        }
    }

    private File getDir() {
        File dir = new File(Environment.getDataSystemCeDirectory(mUserId), "childmode");
        if (!dir.exists() && !dir.mkdirs()) {
            Slog.e(TAG, "Error while creating childmode directory: " + dir);
        }
        return dir;
    }

    public void activate(boolean enable) {
        AppLockManager appLockManager = AppLockManager.getInstance(mContext);
        FirewallManager firewallManager = FirewallManager.getInstance(mContext);
        if (appLockManager.isActivate() != enable)
            appLockManager.activate(enable);
        if (firewallManager.isActivate() != enable)
            firewallManager.activate(enable);
        SystemProperties.set("persist.volla.childmode.enable", enable ? "true" : "false");
        UserManager.get(mContext).setUserRestriction(UserManager.DISALLOW_USER_SWITCH,
            enable, UserHandle.of(mUserId));
    }

    public boolean isActivate() {
        return SystemProperties.getBoolean("persist.volla.childmode.enable", false);
    }

    public boolean setPassword(String password) {
        if (isActivate())
            return false;

        byte[] hash = mDigest.digest(password.getBytes(StandardCharsets.UTF_8));
        try {
            Files.write(Paths.get(getDir().getAbsolutePath() + "/.pass"),
                    hash, StandardOpenOption.CREATE);
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public boolean validatePassword(String password) {
        byte[] hash = mDigest.digest(password.getBytes(StandardCharsets.UTF_8));
        byte[] fileContent = new byte[0];
        try {
            fileContent = Files.readAllBytes(Paths.get(getDir().getAbsolutePath() + "/.pass"));
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        if (Arrays.equals(fileContent, hash))
            return true;

        return false;
    }

    public boolean isPasswortSet() {
        byte[] fileContent = new byte[0];
        try {
            fileContent = Files.readAllBytes(Paths.get(getDir().getAbsolutePath() + "/.pass"));
        } catch (IOException e) {
            return false;
        }

        return true;
    }

    private final IBinder mService = new IChildModeService.Stub() {
        @Override
        public void activate(boolean enable) {
            ChildModeService.this.activate(enable);
        }

        @Override
        public boolean isActivate() {
            return ChildModeService.this.isActivate();
        }

        @Override
        public boolean setPassword(String password) {
            return ChildModeService.this.setPassword(password);
        }

        @Override
        public boolean validatePassword(String password) {
            return ChildModeService.this.validatePassword(password);
        }

        @Override
        public boolean isPasswortSet() {
            return ChildModeService.this.isPasswortSet();
        }
    };
}
