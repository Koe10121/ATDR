// utils/db.js
import { openDB } from 'idb';

const DB_NAME = 'project-name';
const DB_VERSION = 1;
const STORE = 'kv';   // key–value แบบง่าย

/** เปิด (หรืออัปเกรด) DB */
export async function getDB() {
    return openDB(DB_NAME, DB_VERSION, {
        upgrade(db) {
            if (!db.objectStoreNames.contains(STORE)) {
                db.createObjectStore(STORE); // key = string, value = อะไรก็ได้
            }
        }
    });
}

/** บันทึกค่า */
export async function setItem(key, value) {
    const db = await getDB();
    await db.put(STORE, value, key);
}

/** อ่านค่า */
export async function getItem(key) {
    const db = await getDB();
    return db.get(STORE, key);
}

/** ลบค่า */
export async function removeItem(key) {
    const db = await getDB();
    await db.delete(STORE, key);
}
