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

import lineageos.applock.IAppLockCallback;

/** @hide */
interface IAppLockService {

    void activate(boolean enable);

    boolean isActivate();

    void enableInstallLocker(boolean enable);

    boolean isInstallLockerEnabled();

    void addAppToList(String packageName);

    void removeAppFromList(String packageName);

    boolean isAppLocked(String packageName);

    int getLockedAppsCount();

    List<String> getLockedPackages();

    void addAppLockCallback(IAppLockCallback callback);

    void removeAppLockCallback(IAppLockCallback callback);

}
