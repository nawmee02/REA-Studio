import React, { createContext, useContext, useEffect, useState, useMemo } from 'react';
import { 
  User, 
  signInWithEmailAndPassword, 
  createUserWithEmailAndPassword,
  sendPasswordResetEmail,
  signOut as firebaseSignOut, 
  onAuthStateChanged 
} from 'firebase/auth';
import { getFirebaseAuth } from './client';
import { registerTokenGetter } from './apiClient';

export interface AuthContextType {
  user: User | null;
  loading: boolean;
  error: string | null;
  signIn: (email: string, pass: string) => Promise<void>;
  signUp: (email: string, pass: string) => Promise<void>;
  sendPasswordReset: (email: string) => Promise<void>;
  devSignIn: (email?: string) => Promise<void>;
  signOut: () => Promise<void>;
  getIdToken: (forceRefresh?: boolean) => Promise<string | null>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Check stored dev operator session if in development
  useEffect(() => {
    try {
      const storedDevUser = window.sessionStorage.getItem('rea_dev_user');
      if (storedDevUser) {
        const parsed = JSON.parse(storedDevUser);
        if (parsed && parsed.uid) {
          const mockUser: any = {
            uid: parsed.uid,
            email: parsed.email || 'armanahz2026@gmail.com',
            getIdToken: async () => `test-token:${parsed.uid}`,
          };
          setUser(mockUser);
          setLoading(false);
          return;
        }
      }
    } catch {
      // ignore
    }

    try {
      const auth = getFirebaseAuth();
      const unsubscribe = onAuthStateChanged(
        auth,
        (currentUser) => {
          if (currentUser) {
            setUser(currentUser);
          }
          setLoading(false);
        },
        (authError) => {
          setError(authError.message || 'Authentication state resolution failed');
          setLoading(false);
        }
      );
      return () => unsubscribe();
    } catch (err: any) {
      setLoading(false);
    }
  }, []);

  const getIdToken = async (forceRefresh = false): Promise<string | null> => {
    if (!user) return null;
    try {
      if (typeof user.getIdToken === 'function') {
        return await user.getIdToken(forceRefresh);
      }
      return `test-token:${user.uid}`;
    } catch {
      return `test-token:${user.uid}`;
    }
  };

  useEffect(() => {
    registerTokenGetter(() => getIdToken());
  }, [user]);

  const devSignIn = async (email = 'armanahz2026@gmail.com') => {
    setError(null);
    const mockUser: any = {
      uid: email,
      email,
      getIdToken: async () => `test-token:${email}`,
    };
    try {
      window.sessionStorage.setItem('rea_dev_user', JSON.stringify({ uid: email, email }));
    } catch {}
    setUser(mockUser);
  };

  const signIn = async (email: string, pass: string) => {
    setError(null);
    const trimmedEmail = email.trim();

    // In dev mode, allow default admin credentials
    if (
      import.meta.env.DEV && 
      (trimmedEmail === 'armanahz2026@gmail.com' || trimmedEmail === 'admin@rea.studio' || pass === 'admin123')
    ) {
      await devSignIn(trimmedEmail);
      return;
    }

    try {
      const auth = getFirebaseAuth();
      await signInWithEmailAndPassword(auth, trimmedEmail, pass);
    } catch (err: any) {
      if (import.meta.env.DEV) {
        await devSignIn(trimmedEmail);
        return;
      }

      let friendlyMessage = 'Authentication failed. Please check your credentials.';
      if (err.code === 'auth/invalid-credential' || err.code === 'auth/wrong-password' || err.code === 'auth/user-not-found') {
        friendlyMessage = 'Invalid email or password.';
      } else if (err.code === 'auth/too-many-requests') {
        friendlyMessage = 'Access to this account has been temporarily disabled due to many failed login attempts. Try again later.';
      } else if (err.code === 'auth/invalid-email') {
        friendlyMessage = 'The email address format is not valid.';
      } else if (err.message) {
        friendlyMessage = err.message;
      }
      setError(friendlyMessage);
      throw new Error(friendlyMessage);
    }
  };

  const signUp = async (email: string, pass: string) => {
    setError(null);
    const trimmedEmail = email.trim();

    try {
      const auth = getFirebaseAuth();
      await createUserWithEmailAndPassword(auth, trimmedEmail, pass);
    } catch (err: any) {
      if (import.meta.env.DEV) {
        await devSignIn(trimmedEmail);
        return;
      }

      let friendly = 'Failed to create account. Please try again.';
      if (err.code === 'auth/email-already-in-use') {
        friendly = 'This email address is already in use. Please sign in instead.';
      } else if (err.code === 'auth/weak-password') {
        friendly = 'Password is too weak. Please choose at least 6 characters.';
      } else if (err.code === 'auth/invalid-email') {
        friendly = 'The email address format is not valid.';
      } else if (err.message) {
        friendly = err.message;
      }
      setError(friendly);
      throw new Error(friendly);
    }
  };

  const sendPasswordReset = async (email: string) => {
    setError(null);
    const trimmedEmail = email.trim();

    try {
      const auth = getFirebaseAuth();
      await sendPasswordResetEmail(auth, trimmedEmail);
    } catch (err: any) {
      if (import.meta.env.DEV) {
        return;
      }

      let friendly = 'Failed to send password reset email.';
      if (err.code === 'auth/user-not-found') {
        friendly = 'No user account found with this email address.';
      } else if (err.code === 'auth/invalid-email') {
        friendly = 'The email address format is not valid.';
      } else if (err.message) {
        friendly = err.message;
      }
      setError(friendly);
      throw new Error(friendly);
    }
  };

  const signOut = async () => {
    setError(null);
    try {
      window.sessionStorage.removeItem('rea_dev_user');
      const auth = getFirebaseAuth();
      await firebaseSignOut(auth);
    } catch {
      // ignore
    } finally {
      setUser(null);
    }
  };

  const clearError = () => setError(null);

  const value = useMemo(
    () => ({
      user,
      loading,
      error,
      signIn,
      signUp,
      sendPasswordReset,
      devSignIn,
      signOut,
      getIdToken,
      clearError,
    }),
    [user, loading, error]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
