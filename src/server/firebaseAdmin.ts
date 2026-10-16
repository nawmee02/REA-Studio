import { initializeApp, getApps, getApp, App } from 'firebase-admin/app';
import { getFirestore, Firestore } from 'firebase-admin/firestore';
import { getAuth, Auth } from 'firebase-admin/auth';
import fs from 'fs';
import path from 'path';

let initializedApp: App | null = null;
let firestoreInstance: Firestore | null = null;
let authInstance: Auth | null = null;

export interface FirebaseServerConfig {
  projectId: string;
  databaseId: string;
  storageBackend: 'firestore' | 'sqlite';
  adminUids: string[];
}

export function resolveServerConfig(): FirebaseServerConfig {
  let projectId = process.env.FIREBASE_PROJECT_ID;
  let databaseId = process.env.FIREBASE_DATABASE_ID;
  const storageBackend = (process.env.FIREBASE_STORAGE_BACKEND?.toLowerCase() === 'sqlite' || (process.env.NODE_ENV === 'test' && process.env.FIREBASE_STORAGE_BACKEND !== 'firestore')) ? 'sqlite' : 'firestore';
  
  const adminUidsEnv = process.env.FIREBASE_ADMIN_UIDS || '';
  const adminUids = adminUidsEnv
    .split(',')
    .map(u => u.trim())
    .filter(Boolean);

  try {
    const configPath = path.join(process.cwd(), 'firebase-applet-config.json');
    if (fs.existsSync(configPath)) {
      const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      if (!projectId && cfg.projectId) projectId = cfg.projectId;
      if (!databaseId && cfg.firestoreDatabaseId) databaseId = cfg.firestoreDatabaseId;
    }
  } catch {
    // ignore
  }

  return {
    projectId: projectId || 'ai-studio-applet-webapp-8d0c9',
    databaseId: databaseId || '(default)',
    storageBackend,
    adminUids,
  };
}

export function getAdminApp(): App {
  if (!initializedApp) {
    const apps = getApps();
    if (apps.length > 0) {
      initializedApp = apps[0];
    } else {
      const config = resolveServerConfig();
      initializedApp = initializeApp({
        projectId: config.projectId,
      });
    }
  }
  return initializedApp;
}

export function getAdminAuth(): Auth {
  if (!authInstance) {
    authInstance = getAuth(getAdminApp());
  }
  return authInstance;
}

export function getAdminFirestore(): Firestore {
  if (!firestoreInstance) {
    const app = getAdminApp();
    const config = resolveServerConfig();
    if (config.databaseId && config.databaseId !== '(default)') {
      try {
        firestoreInstance = getFirestore(app, config.databaseId);
      } catch {
        firestoreInstance = getFirestore(app);
      }
    } else {
      firestoreInstance = getFirestore(app);
    }
  }
  return firestoreInstance;
}
