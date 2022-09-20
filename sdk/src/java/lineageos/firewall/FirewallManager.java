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

package lineageos.firewall;

import android.content.Context;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.ServiceManager.ServiceNotFoundException;
import android.util.Log;

import lineageos.app.LineageContextConstants;

import java.util.List;

public class FirewallManager {
    private static final String TAG = "FirewallManager";

    private static IFirewallService sService;
    private static FirewallManager sInstance;

    private Context mContext;

    private FirewallManager(Context context) {
        Context appContext = context.getApplicationContext();
        mContext = appContext == null ? context : appContext;
        sService = getService();
        if (sService == null) {
            throw new RuntimeException("Unable to get FirewallService. The service" +
                    " either crashed, was not started, or the interface has been called to early" +
                    " in SystemServer init");
        }
    }

    public static FirewallManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new FirewallManager(context);
        }
        return sInstance;
    }

    /** @hide **/
    public static IFirewallService getService() {
        if (sService != null) {
            return sService;
        }
        IBinder b = ServiceManager.getService(LineageContextConstants.VOLLA_FIREWALL_SERVICE);

        if (b == null) {
            Log.e(TAG, "null service. SAD!");
            return null;
        }

        sService = IFirewallService.Stub.asInterface(b);
        return sService;
    }

    public FirewallManager(IFirewallService service) {
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

    public void blacklistMode(boolean enable) {
        try {
            sService.blacklistMode(enable);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public boolean isBlacklistMode() {
        try {
            return sService.isBlacklistMode();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public void addDomainToList(String domain) {
        try {
            sService.addDomainToList(domain);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public void removeDomainFromList(String domain) {
        try {
            sService.removeDomainFromList(domain);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public boolean isDomainOnList(String domain) {
        try {
            return sService.isDomainOnList(domain);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public int getDomainsListCount() {
        try {
            return sService.getDomainsListCount();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public List<String> getDomainsList() {
        try {
            return sService.getDomainsList();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    public void clearDomainList() {
        try {
            sService.clearDomainList();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }
}
