/**
 * Copyright (C) 2021 Paranoid Android
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

package lineageos.applock;

import android.content.Context;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.ServiceManager.ServiceNotFoundException;
import android.util.Log;

import lineageos.app.LineageContextConstants;

import java.util.List;

public class AppLockManager {
    private static final String TAG = "AppLockManager";

    private static IAppLockService sService;
    private static AppLockManager sInstance;

    private Context mContext;

    private AppLockManager(Context context) {
        Context appContext = context.getApplicationContext();
        mContext = appContext == null ? context : appContext;
        sService = getService();
        if (sService == null) {
            throw new RuntimeException("Unable to get AppLockService. The service" +
                    " either crashed, was not started, or the interface has been called to early" +
                    " in SystemServer init");
        }
    }

    public static AppLockManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new AppLockManager(context);
        }
        return sInstance;
    }

    /** @hide **/
    public static IAppLockService getService() {
        if (sService != null) {
            return sService;
        }
        IBinder b = ServiceManager.getService(LineageContextConstants.VOLLA_APPLOCK_SERVICE);

        if (b == null) {
            Log.e(TAG, "null service. SAD!");
            return null;
        }

        sService = IAppLockService.Stub.asInterface(b);
        return sService;
    }

    public AppLockManager(IAppLockService service) {
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

    public void enableInstallLocker(boolean enable) {
        try {
            sService.enableInstallLocker(enable);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public boolean isInstallLockerEnabled() {
        try {
            return sService.isInstallLockerEnabled();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public void addAppToList(String packageName) {
        try {
            sService.addAppToList(packageName);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public void removeAppFromList(String packageName) {
        try {
            sService.removeAppFromList(packageName);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public boolean isAppLocked(String packageName) {
        try {
            return sService.isAppLocked(packageName);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public int getLockedAppsCount() {
        try {
            return sService.getLockedAppsCount();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public List<String> getLockedPackages() {
        try {
            return sService.getLockedPackages();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public void addAppLockCallback(IAppLockCallback c) {
        try {
            sService.addAppLockCallback(c);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public void removeAppLockCallback(IAppLockCallback c) {
        try {
            sService.removeAppLockCallback(c);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public abstract static class AppLockCallback extends IAppLockCallback.Stub {
        @Override
        public abstract void onAppStateChanged(String pkg);
    };
}
