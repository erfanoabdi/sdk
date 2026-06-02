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

import android.content.ContentValues;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Slog;

import lineageos.firewall.BlockEventSchema;

class FirewallBlockDatabase extends SQLiteOpenHelper {

    private static final String TAG = "FirewallBlockDatabase";

    private static final String CREATE_TABLE =
        "CREATE TABLE " + BlockEventSchema.TABLE + " ("
        + BlockEventSchema.COL_ID            + " INTEGER PRIMARY KEY AUTOINCREMENT,"
        + BlockEventSchema.COL_TIMESTAMP     + " INTEGER NOT NULL,"
        + BlockEventSchema.COL_DOMAIN        + " TEXT NOT NULL,"
        + BlockEventSchema.COL_APP_NAME      + " TEXT,"
        + BlockEventSchema.COL_APP_PKG       + " TEXT,"
        + BlockEventSchema.COL_IS_HTTPS      + " INTEGER NOT NULL DEFAULT 0,"
        + BlockEventSchema.COL_IS_BLACKLIST  + " INTEGER NOT NULL DEFAULT 0,"
        + BlockEventSchema.COL_SOURCE_TYPE   + " TEXT NOT NULL DEFAULT 'manual',"
        + BlockEventSchema.COL_TEMPLATE_NAME + " TEXT,"
        + BlockEventSchema.COL_ALLOWED_TYPE  + " TEXT,"
        + BlockEventSchema.COL_ALLOWED_AT    + " INTEGER NOT NULL DEFAULT 0"
        + ")";

    FirewallBlockDatabase(Context context, String path) {
        super(context, path, null, BlockEventSchema.DB_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(CREATE_TABLE);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // Future migrations go here.
        Slog.w(TAG, "Upgrading block event DB from " + oldVersion + " to " + newVersion);
        db.execSQL("DROP TABLE IF EXISTS " + BlockEventSchema.TABLE);
        onCreate(db);
    }

    long insertEvent(long timestamp, String domain, String appName, String appPkg,
            boolean isHttps, boolean isBlacklist, String sourceType, String templateName) {
        ContentValues v = new ContentValues(9);
        v.put(BlockEventSchema.COL_TIMESTAMP,     timestamp);
        v.put(BlockEventSchema.COL_DOMAIN,        domain);
        v.put(BlockEventSchema.COL_APP_NAME,      appName);
        v.put(BlockEventSchema.COL_APP_PKG,       appPkg);
        v.put(BlockEventSchema.COL_IS_HTTPS,      isHttps ? 1 : 0);
        v.put(BlockEventSchema.COL_IS_BLACKLIST,  isBlacklist ? 1 : 0);
        v.put(BlockEventSchema.COL_SOURCE_TYPE,   sourceType);
        v.put(BlockEventSchema.COL_TEMPLATE_NAME, templateName);
        try {
            return getWritableDatabase().insert(BlockEventSchema.TABLE, null, v);
        } catch (Exception e) {
            Slog.e(TAG, "insertEvent failed", e);
            return -1;
        }
    }

    void updateAllowed(String domain, String allowedType) {
        try {
            ContentValues v = new ContentValues(2);
            v.put(BlockEventSchema.COL_ALLOWED_TYPE, allowedType);
            v.put(BlockEventSchema.COL_ALLOWED_AT,   System.currentTimeMillis());
            getWritableDatabase().execSQL(
                "UPDATE " + BlockEventSchema.TABLE
                + " SET " + BlockEventSchema.COL_ALLOWED_TYPE + "=?,"
                           + BlockEventSchema.COL_ALLOWED_AT   + "=?"
                + " WHERE " + BlockEventSchema.COL_DOMAIN + "=?"
                + "   AND "  + BlockEventSchema.COL_ALLOWED_TYPE + " IS NULL"
                + " ORDER BY " + BlockEventSchema.COL_ID + " DESC LIMIT 1",
                new Object[]{allowedType, System.currentTimeMillis(), domain});
        } catch (Exception e) {
            Slog.e(TAG, "updateAllowed failed for " + domain, e);
        }
    }

    void clearEvents() {
        try {
            getWritableDatabase().delete(BlockEventSchema.TABLE, null, null);
        } catch (Exception e) {
            Slog.e(TAG, "clearEvents failed", e);
        }
    }

    void checkpoint() {
        try {
            getWritableDatabase().execSQL("PRAGMA wal_checkpoint(TRUNCATE)");
        } catch (Exception e) {
            Slog.e(TAG, "checkpoint failed", e);
        }
    }
}
