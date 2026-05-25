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

import android.os.Parcel;
import android.os.Parcelable;

public class DomainListInfo implements Parcelable {

    public String id;
    public String title;
    public String url;
    public double version;
    public boolean isBlacklist;

    public DomainListInfo() {}

    protected DomainListInfo(Parcel in) {
        id = in.readString();
        title = in.readString();
        url = in.readString();
        version = in.readDouble();
        isBlacklist = in.readBoolean();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(id);
        dest.writeString(title);
        dest.writeString(url);
        dest.writeDouble(version);
        dest.writeBoolean(isBlacklist);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<DomainListInfo> CREATOR = new Creator<DomainListInfo>() {
        @Override
        public DomainListInfo createFromParcel(Parcel in) {
            return new DomainListInfo(in);
        }

        @Override
        public DomainListInfo[] newArray(int size) {
            return new DomainListInfo[size];
        }
    };
}
