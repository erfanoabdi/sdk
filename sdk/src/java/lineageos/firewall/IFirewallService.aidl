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

import lineageos.firewall.AllowedDomain;
import lineageos.firewall.DomainListInfo;

/** @hide */
interface IFirewallService {

    void activate(boolean enable);

    boolean isActivate();

    void blacklistMode(boolean enable);

    boolean isBlacklistMode();

    void addDomainToList(String domain);

    void removeDomainFromList(String domain);

    boolean isDomainOnList(String domain);

    int getDomainsListCount();

    List<String> getDomainsList();

    void clearDomainList();

    void addDomainListToList(in List<String> domains);

    List<String> getManualDomains();

    void addDomainList(in DomainListInfo info, in List<String> domains);

    void removeDomainList(String id);

    List<DomainListInfo> getDomainLists();

    void addAppToList(String app);

    void removeAppFromList(String app);

    boolean isAppOnList(String app);

    int getAppsListCount();

    List<String> getAppsList();

    void alertMode(boolean enable);

    boolean isAlertMode();

    List<AllowedDomain> getAllowedDomains();

    void removeAllowedDomain(String name);

    ParcelFileDescriptor getBlockEventsDb();

    void clearBlockEvents();

}
