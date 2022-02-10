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

import android.content.Context;
import android.os.SystemProperties;
import android.os.IBinder;
import android.util.Slog;

import lineageos.childmode.IChildModeService;
import lineageos.applock.AppLockManager;
import lineageos.firewall.FirewallManager;
import lineageos.app.LineageContextConstants;

import com.android.internal.R;
import com.android.server.LocalServices;
import com.android.server.SystemService;

public class ChildModeService extends LineageSystemService {

    private static final String TAG = "ChildModeService";
    private static final boolean DEBUG_CHILDMODE = true;

    private Context mContext;

    public ChildModeService(Context context) {
        super(context);
        mContext = context;
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

    public void activate(boolean enable) {
        AppLockManager appLockManager = AppLockManager.getInstance(mContext);
        FirewallManager firewallManager = FirewallManager.getInstance(mContext);
        if (appLockManager.isActivate() != enable)
            appLockManager.activate(enable);
        if (firewallManager.isActivate() != enable)
            firewallManager.activate(enable);
        SystemProperties.set("persist.volla.childmode.enable", enable ? "true" : "false");
    }

    public boolean isActivate() {
        return SystemProperties.getBoolean("persist.volla.childmode.enable", false);
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
    };
}
