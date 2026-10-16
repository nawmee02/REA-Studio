import { initializeApp, getApps, getApp, FirebaseApp } from 'firebase/app';
import { getAuth, Auth } from 'firebase/auth';

interface FirebaseClientConfig {
  apiKey: string;
  authDomain: string;
  projectId: string;
  appId: string;
}

function resolveFirebaseConfig(): FirebaseClientConfig {
  const envApiKey = import.meta.env.VITE_FIREBASE_API_KEY;
  const envAuthDomain = import.meta.env.VITE_FIREBASE_AUTH_DOMAIN;
  const envProjectId = import.meta.env.VITE_FIREBASE_PROJECT_ID;
  const envAppId = import.meta.env.VITE_FIREBASE_APP_ID;

  if (envApiKey && envAuthDomain && envProjectId && envAppId) {
    return {
      apiKey: envApiKey,
      authDomain: envAuthDomain,
      projectId: envProjectId,
      appId: envAppId,
    };
  }

  // Fallback to bundled firebase-applet-config.json if available
  try {
    // Dynamic access to avoid build break if not present
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const appletConfig = (window as any).__FIREBASE_CONFIG__;
    if (appletConfig && appletConfig.apiKey && appletConfig.projectId) {
      return {
        apiKey: appletConfig.apiKey,
        authDomain: appletConfig.authDomain || `${appletConfig.projectId}.firebaseapp.com`,
        projectId: appletConfig.projectId,
        appId: appletConfig.appId,
      };
    }
  } catch {
    // ignore
  }

  // Attempt import from firebase-applet-config.json
  try {
    const config = import.meta.glob('/firebase-applet-config.json', { eager: true });
    const keys = Object.keys(config);
    if (keys.length > 0) {
      const cfg = (config[keys[0]] as any).default || config[keys[0]];
      if (cfg && cfg.apiKey && cfg.projectId) {
        return {
          apiKey: cfg.apiKey,
          authDomain: cfg.authDomain || `${cfg.projectId}.firebaseapp.com`,
          projectId: cfg.projectId,
          appId: cfg.appId,
        };
      }
    }
  } catch {
    // ignore
  }

  throw new Error(
    'Firebase client configuration missing. Provide VITE_FIREBASE_API_KEY, VITE_FIREBASE_AUTH_DOMAIN, VITE_FIREBASE_PROJECT_ID, and VITE_FIREBASE_APP_ID in your environment, or configure firebase-applet-config.json.'
  );
}

let app: FirebaseApp;
let auth: Auth;

export function getFirebaseApp(): FirebaseApp {
  if (!app) {
    const apps = getApps();
    if (apps.length > 0) {
      app = getApp();
    } else {
      const config = resolveFirebaseConfig();
      app = initializeApp(config);
    }
  }
  return app;
}

export function getFirebaseAuth(): Auth {
  if (!auth) {
    const currentApp = getFirebaseApp();
    auth = getAuth(currentApp);
  }
  return auth;
}
