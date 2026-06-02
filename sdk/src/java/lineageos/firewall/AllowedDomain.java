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

public class AllowedDomain implements Parcelable {

    public String name;
    /** Expiry timestamp in milliseconds since epoch, or -1 for permanent. */
    public long expiry;

    public AllowedDomain() {}

    public AllowedDomain(String name, long expiry) {
        this.name = name;
        this.expiry = expiry;
    }

    protected AllowedDomain(Parcel in) {
        name = in.readString();
        expiry = in.readLong();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(name);
        dest.writeLong(expiry);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<AllowedDomain> CREATOR = new Creator<AllowedDomain>() {
        @Override
        public AllowedDomain createFromParcel(Parcel in) {
            return new AllowedDomain(in);
        }

        @Override
        public AllowedDomain[] newArray(int size) {
            return new AllowedDomain[size];
        }
    };
}
