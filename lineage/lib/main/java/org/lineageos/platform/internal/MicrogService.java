/*
 * Copyright (C) 2018 The LineageOS Project
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

import android.content.Context;
import android.os.ServiceManager;
import android.util.Log;
import android.util.Slog;
import android.net.Uri;

import com.android.server.pm.PackageManagerService;

import lineageos.app.LineageContextConstants;
import lineageos.preference.SettingsHelper;
import lineageos.providers.LineageSettings;

import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DEFAULT;

/** @hide */
public class MicrogService extends LineageSystemService {
    private static final String TAG = "MicrogService";
    private final Uri ENABLE_MICROG_URI =
            LineageSettings.System.getUriFor(LineageSettings.System.ENABLE_MICROG);

    private final Context mContext;
    private final PackageManagerService mPm;

    private static final String[] MICROG_PACKAGES = new String[]{
            "com.google.android.gms",
            "com.android.vending"
    };
    private static final String VOLLA_NLP_PACKAGE = "com.volla.nlp";

    public MicrogService(Context context) {
        super(context);
        mContext = context;
        mPm = (PackageManagerService) ServiceManager.getService("package");
    }

    @Override
    public String getFeatureDeclaration() {
        return LineageContextConstants.Features.HARDWARE_ABSTRACTION;
    }

    @Override
    public void onStart() {
        Slog.v(TAG, "Starting Service");
    }

    @Override
    public void onUnlockUser(int userId) {
        Slog.v(TAG, "Loading Service");
        settingChanged(userId);
        SettingsHelper.get(mContext).startWatching(new SettingsHelper.OnSettingsChangeListener() {
            @Override
            public void onSettingsChanged(Uri settingsUri) {
                settingChanged(userId);
            }
        }, ENABLE_MICROG_URI);
    }

    private void settingChanged(int userId) {
       int value = LineageSettings.System.getIntForUser(mContext.getContentResolver(),
               LineageSettings.System.ENABLE_MICROG, 0, userId);
       for (String packageId : MICROG_PACKAGES) {
           setAppEnabled(packageId, value == 1, userId);
       }
       setAppEnabled(VOLLA_NLP_PACKAGE, value != 1, userId);
    }

    private void setAppEnabled(String packageName, boolean enabled, int userId) {
        int currentState = mPm.getApplicationEnabledSetting(packageName, userId);
        boolean isCurrentEnabled = (currentState == COMPONENT_ENABLED_STATE_DEFAULT) || (currentState == COMPONENT_ENABLED_STATE_ENABLED);
        if (isCurrentEnabled != enabled) {
            int state = enabled ? COMPONENT_ENABLED_STATE_ENABLED : COMPONENT_ENABLED_STATE_DISABLED;
            mPm.setApplicationEnabledSetting(packageName, state, 0, userId, TAG);
        }
    }
}
