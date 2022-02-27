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

package lineageos.childmode;

import android.content.Context;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.ServiceManager.ServiceNotFoundException;
import android.util.Log;

import lineageos.app.LineageContextConstants;

import java.util.List;

public class ChildModeManager {
    private static final String TAG = "ChildModeManager";

    private static IChildModeService sService;
    private static ChildModeManager sInstance;

    private Context mContext;

    private ChildModeManager(Context context) {
        Context appContext = context.getApplicationContext();
        mContext = appContext == null ? context : appContext;
        sService = getService();
        if (sService == null) {
            throw new RuntimeException("Unable to get ChildModeService. The service" +
                    " either crashed, was not started, or the interface has been called to early" +
                    " in SystemServer init");
        }
    }

    public static ChildModeManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new ChildModeManager(context);
        }
        return sInstance;
    }

    /** @hide **/
    public static IChildModeService getService() {
        if (sService != null) {
            return sService;
        }
        IBinder b = ServiceManager.getService(LineageContextConstants.VOLLA_CHILDMODE_SERVICE);

        if (b == null) {
            Log.e(TAG, "null service. SAD!");
            return null;
        }

        sService = IChildModeService.Stub.asInterface(b);
        return sService;
    }

    public ChildModeManager(IChildModeService service) {
        sService = service;
    }

    public void activate(boolean enable) {
        try {
            sService.activate(enable);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public boolean isActivate() {
        try {
            return sService.isActivate();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public boolean setPassword(String password) {
        try {
            return sService.setPassword(password);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public boolean validatePassword(String password) {
        try {
            return sService.validatePassword(password);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public boolean isPasswortSet() {
        try {
            return sService.isPasswortSet();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }
}
