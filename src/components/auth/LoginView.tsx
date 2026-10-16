import React, { useState, useId } from 'react';
import { useAuth } from '../../firebase/AuthProvider';
import { 
  Terminal, 
  Shield, 
  Lock, 
  Mail, 
  AlertCircle, 
  ArrowRight, 
  KeyRound, 
  Sparkles, 
  UserCheck, 
  UserPlus, 
  CheckCircle2, 
  ArrowLeft,
  Eye,
  EyeOff,
  Check,
  X,
  User,
  ShieldCheck,
  RefreshCw
} from 'lucide-react';

type AuthMode = 'signin' | 'signup' | 'forgot_password';

interface PasswordCriteria {
  minChars: boolean;
  hasUpper: boolean;
  hasLower: boolean;
  hasNumber: boolean;
  hasSpecial: boolean;
}

export const LoginView: React.FC = () => {
  const { signIn, signUp, sendPasswordReset, devSignIn, error, clearError } = useAuth();
  
  const [mode, setMode] = useState<AuthMode>('signin');
  const [email, setEmail] = useState('armanahz2026@gmail.com');
  const [password, setPassword] = useState('admin123');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [agreeTerms, setAgreeTerms] = useState(true);
  
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [resetSentEmail, setResetSentEmail] = useState<string | null>(null);
  const [resendCooldown, setResendCooldown] = useState(0);

  const emailInputId = useId();
  const passwordInputId = useId();
  const confirmPasswordInputId = useId();
  const nameInputId = useId();

  // Real-time password strength calculation
  const criteria: PasswordCriteria = {
    minChars: password.length >= 8,
    hasUpper: /[A-Z]/.test(password),
    hasLower: /[a-z]/.test(password),
    hasNumber: /[0-9]/.test(password),
    hasSpecial: /[^A-Za-z0-9]/.test(password),
  };

  const strengthScore = Object.values(criteria).filter(Boolean).length;
  
  const getStrengthLabel = (score: number) => {
    if (password.length === 0) return { label: 'None', color: 'bg-slate-700', text: 'text-slate-500' };
    if (score <= 2) return { label: 'Weak', color: 'bg-rose-500', text: 'text-rose-400' };
    if (score === 3) return { label: 'Fair', color: 'bg-amber-500', text: 'text-amber-400' };
    if (score === 4) return { label: 'Good', color: 'bg-emerald-500', text: 'text-emerald-400' };
    return { label: 'Strong', color: 'bg-indigo-500', text: 'text-indigo-400' };
  };

  const strength = getStrengthLabel(strengthScore);

  const switchMode = (newMode: AuthMode) => {
    setMode(newMode);
    clearError();
    setLocalError(null);
    setResetSentEmail(null);
  };

  const handlePasswordReset = async (targetEmail: string) => {
    const trimmed = targetEmail.trim();
    if (!trimmed || !trimmed.includes('@')) {
      setLocalError('Please enter a valid email address to receive reset instructions.');
      return;
    }

    try {
      setSubmitting(true);
      setLocalError(null);
      await sendPasswordReset(trimmed);
      setResetSentEmail(trimmed);
      setResendCooldown(30);

      // Countdown timer for resend
      const timer = setInterval(() => {
        setResendCooldown((prev) => {
          if (prev <= 1) {
            clearInterval(timer);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    } catch (err: any) {
      // Error handled by AuthContext
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    setLocalError(null);

    const trimmedEmail = email.trim();
    if (!trimmedEmail || !trimmedEmail.includes('@')) {
      setLocalError('Please provide a valid email address.');
      return;
    }

    if (mode === 'forgot_password') {
      await handlePasswordReset(trimmedEmail);
      return;
    }

    if (!password) {
      setLocalError('Please enter your password.');
      return;
    }

    if (mode === 'signup') {
      if (password.length < 8) {
        setLocalError('Password must be at least 8 characters.');
        return;
      }
      if (password !== confirmPassword) {
        setLocalError('Passwords do not match. Please re-enter your password confirmation.');
        return;
      }
      if (!agreeTerms) {
        setLocalError('Please accept the Security Policy & Terms of Use to proceed.');
        return;
      }

      try {
        setSubmitting(true);
        await signUp(trimmedEmail, password);
      } catch (err: any) {
        // Error handled in AuthContext
      } finally {
        setSubmitting(false);
      }
      return;
    }

    // Default: Sign In
    try {
      setSubmitting(true);
      await signIn(trimmedEmail, password);
    } catch (err: any) {
      // Error handled in AuthContext
    } finally {
      setSubmitting(false);
    }
  };

  const handleQuickLogin = async () => {
    clearError();
    setLocalError(null);
    try {
      setSubmitting(true);
      await devSignIn('armanahz2026@gmail.com');
    } finally {
      setSubmitting(false);
    }
  };

  const activeError = localError || error;

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center px-4 py-8 sm:py-12 selection:bg-indigo-500 selection:text-white relative">
      {/* Dynamic ambient lighting & grid backdrop */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[32rem] h-[32rem] bg-indigo-600/10 rounded-full blur-[100px]" />
        <div className="absolute top-1/2 right-1/4 w-96 h-96 bg-violet-600/10 rounded-full blur-[120px]" />
        <div className="absolute -bottom-20 left-1/4 w-80 h-80 bg-emerald-600/5 rounded-full blur-[100px]" />
        
        {/* Subtle grid pattern */}
        <div 
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, #ffffff 1px, transparent 0)`,
            backgroundSize: '24px 24px'
          }}
        />
      </div>

      <div className="relative w-full max-w-[460px] z-10">
        {/* Brand Header */}
        <div className="text-center mb-6 sm:mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-tr from-indigo-600 via-indigo-500 to-violet-500 shadow-xl shadow-indigo-500/20 mb-3 border border-indigo-400/30 ring-4 ring-indigo-500/10">
            <Terminal className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center justify-center gap-2">
            <span>REA Studio</span>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
              v6.5
            </span>
          </h1>
          <p className="mt-1.5 text-xs text-slate-400 max-w-sm mx-auto leading-relaxed">
            Evidence Provenance &bull; Cryptographic Replay &bull; Target Intelligence
          </p>
        </div>

        {/* Main Card */}
        <div className="bg-slate-900/90 backdrop-blur-2xl border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl shadow-black/60 relative">
          {/* Card Header & Security Badge */}
          <div className="flex items-center justify-between pb-4 mb-5 border-b border-slate-800/80">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-indigo-400" />
              <h2 className="text-sm font-semibold text-slate-200">
                {mode === 'signin' && 'Sign In to Workspace'}
                {mode === 'signup' && 'Create Operator Account'}
                {mode === 'forgot_password' && 'Password Recovery'}
              </h2>
            </div>
            <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>Identity Guard</span>
            </div>
          </div>

          {/* Mode Switcher Tabs (when not in recovery mode) */}
          {mode !== 'forgot_password' && (
            <div className="grid grid-cols-2 rounded-xl bg-slate-950 p-1 mb-5 border border-slate-800/90">
              <button
                type="button"
                onClick={() => switchMode('signin')}
                className={`py-2 text-xs font-medium rounded-lg transition-all duration-150 cursor-pointer ${
                  mode === 'signin'
                    ? 'bg-indigo-600 text-white shadow-sm font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => switchMode('signup')}
                className={`py-2 text-xs font-medium rounded-lg transition-all duration-150 cursor-pointer ${
                  mode === 'signup'
                    ? 'bg-indigo-600 text-white shadow-sm font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                Create Account
              </button>
            </div>
          )}

          {/* Active Error Notice */}
          {activeError && (
            <div 
              role="alert" 
              className="mb-5 p-3.5 rounded-xl bg-rose-950/40 border border-rose-500/30 text-rose-200 text-xs flex items-start gap-2.5 animate-fadeIn"
            >
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1 leading-relaxed text-[12px]">{activeError}</div>
              <button 
                type="button" 
                onClick={() => { clearError(); setLocalError(null); }}
                className="text-rose-400 hover:text-rose-200 p-0.5"
                title="Dismiss"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {/* Success Notification for Password Recovery */}
          {resetSentEmail && mode === 'forgot_password' && (
            <div className="mb-6 p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/30 text-emerald-200 text-xs animate-fadeIn">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <div className="flex-1 space-y-1">
                  <h4 className="font-semibold text-emerald-300 text-sm">Recovery Link Sent</h4>
                  <p className="text-emerald-200/80 leading-relaxed text-[12px]">
                    We have dispatched password reset instructions to <strong className="text-white font-mono">{resetSentEmail}</strong>. Please check your inbox and follow the secure link.
                  </p>
                  <p className="text-[11px] text-emerald-300/60 pt-1">
                    Didn't receive the email? Check your spam filter or request another link in{' '}
                    {resendCooldown > 0 ? (
                      <span className="font-mono text-emerald-300 font-semibold">{resendCooldown}s</span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => handlePasswordReset(resetSentEmail)}
                        className="underline text-emerald-300 hover:text-white cursor-pointer"
                      >
                        resend now
                      </button>
                    )}.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Authentication Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Optional Full Name / Call-Sign in Sign Up */}
            {mode === 'signup' && (
              <div>
                <label htmlFor={nameInputId} className="block text-xs font-medium text-slate-300 mb-1.5">
                  Operator Name / Call-Sign <span className="text-slate-500 font-normal">(Optional)</span>
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                    <User className="w-4 h-4" />
                  </div>
                  <input
                    id={nameInputId}
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="e.g. Lead Reverse Engineer"
                    autoComplete="name"
                    className="w-full pl-9 pr-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all"
                  />
                </div>
              </div>
            )}

            {/* Email Field */}
            <div>
              <label htmlFor={emailInputId} className="block text-xs font-medium text-slate-300 mb-1.5">
                Authorized Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  id={emailInputId}
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@domain.com"
                  autoComplete="email"
                  required
                  className="w-full pl-9 pr-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono"
                />
              </div>
            </div>

            {/* Password Field */}
            {mode !== 'forgot_password' && (
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label htmlFor={passwordInputId} className="text-xs font-medium text-slate-300">
                    {mode === 'signup' ? 'Create Password' : 'Password'}
                  </label>
                  {mode === 'signin' && (
                    <button
                      type="button"
                      onClick={() => switchMode('forgot_password')}
                      className="text-[11px] text-indigo-400 hover:text-indigo-300 transition-colors cursor-pointer"
                    >
                      Forgot password?
                    </button>
                  )}
                </div>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    id={passwordInputId}
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
                    required
                    className="w-full pl-9 pr-10 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
                    title={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>

                {/* Password Strength Meter for Sign Up */}
                {mode === 'signup' && password.length > 0 && (
                  <div className="mt-2.5 space-y-2 p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-400">Password Strength:</span>
                      <span className={`font-semibold ${strength.text}`}>{strength.label}</span>
                    </div>

                    {/* Progress segments */}
                    <div className="grid grid-cols-5 gap-1.5 h-1.5">
                      {[1, 2, 3, 4, 5].map((lvl) => (
                        <div
                          key={lvl}
                          className={`rounded-full transition-all duration-300 ${
                            strengthScore >= lvl ? strength.color : 'bg-slate-800'
                          }`}
                        />
                      ))}
                    </div>

                    {/* Criteria checklist */}
                    <div className="grid grid-cols-2 gap-x-2 gap-y-1 pt-1 text-[10px] text-slate-400">
                      <span className={`flex items-center gap-1.5 ${criteria.minChars ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {criteria.minChars ? <Check className="w-3 h-3 text-emerald-400" /> : <span className="w-1.5 h-1.5 rounded-full bg-slate-600 ml-0.5 mr-1" />}
                        At least 8 characters
                      </span>
                      <span className={`flex items-center gap-1.5 ${criteria.hasUpper && criteria.hasLower ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {criteria.hasUpper && criteria.hasLower ? <Check className="w-3 h-3 text-emerald-400" /> : <span className="w-1.5 h-1.5 rounded-full bg-slate-600 ml-0.5 mr-1" />}
                        Upper &amp; lowercase
                      </span>
                      <span className={`flex items-center gap-1.5 ${criteria.hasNumber ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {criteria.hasNumber ? <Check className="w-3 h-3 text-emerald-400" /> : <span className="w-1.5 h-1.5 rounded-full bg-slate-600 ml-0.5 mr-1" />}
                        At least 1 number
                      </span>
                      <span className={`flex items-center gap-1.5 ${criteria.hasSpecial ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {criteria.hasSpecial ? <Check className="w-3 h-3 text-emerald-400" /> : <span className="w-1.5 h-1.5 rounded-full bg-slate-600 ml-0.5 mr-1" />}
                        Special character
                      </span>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Confirm Password Field (Sign Up) */}
            {mode === 'signup' && (
              <div>
                <label htmlFor={confirmPasswordInputId} className="block text-xs font-medium text-slate-300 mb-1.5">
                  Confirm Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    id={confirmPasswordInputId}
                    type={showConfirmPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="••••••••••••"
                    autoComplete="new-password"
                    required
                    className={`w-full pl-9 pr-10 py-2.5 bg-slate-950 border rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 transition-all ${
                      confirmPassword && password === confirmPassword
                        ? 'border-emerald-500/50 focus:border-emerald-500'
                        : confirmPassword && password !== confirmPassword
                          ? 'border-rose-500/50 focus:border-rose-500'
                          : 'border-slate-800 focus:border-indigo-500'
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
                    title={showConfirmPassword ? 'Hide password' : 'Show password'}
                  >
                    {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {confirmPassword && password === confirmPassword && (
                  <p className="mt-1 text-[11px] text-emerald-400 flex items-center gap-1">
                    <Check className="w-3 h-3" /> Passwords match
                  </p>
                )}
              </div>
            )}

            {/* Checkboxes & Preferences */}
            {mode === 'signin' && (
              <div className="flex items-center justify-between text-xs text-slate-400 pt-0.5">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="w-3.5 h-3.5 rounded bg-slate-950 border-slate-700 text-indigo-600 focus:ring-indigo-500/30"
                  />
                  <span>Keep me signed in</span>
                </label>
              </div>
            )}

            {mode === 'signup' && (
              <div className="pt-0.5">
                <label className="flex items-start gap-2 cursor-pointer select-none text-[11px] text-slate-400 leading-relaxed">
                  <input
                    type="checkbox"
                    checked={agreeTerms}
                    onChange={(e) => setAgreeTerms(e.target.checked)}
                    className="w-3.5 h-3.5 mt-0.5 rounded bg-slate-950 border-slate-700 text-indigo-600 focus:ring-indigo-500/30"
                  />
                  <span>
                    I accept the <span className="text-slate-300 font-medium">Safe Reverse Engineering Guidelines</span>, Origin-Bound Probe Limits, and Anti-SSRF Security Rules.
                  </span>
                </label>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={submitting}
              className="w-full mt-3 py-2.5 px-4 rounded-xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white font-medium text-xs flex items-center justify-center gap-2 transition-all shadow-lg shadow-indigo-600/25 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer active:scale-[0.99]"
            >
              {submitting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>
                    {mode === 'signin' && 'Authenticating...'}
                    {mode === 'signup' && 'Creating Account...'}
                    {mode === 'forgot_password' && 'Transmitting Recovery Link...'}
                  </span>
                </>
              ) : mode === 'signin' ? (
                <>
                  <KeyRound className="w-4 h-4" />
                  <span>Sign In to REA Studio</span>
                  <ArrowRight className="w-3.5 h-3.5 opacity-70" />
                </>
              ) : mode === 'signup' ? (
                <>
                  <UserPlus className="w-4 h-4" />
                  <span>Register &amp; Launch Studio</span>
                  <ArrowRight className="w-3.5 h-3.5 opacity-70" />
                </>
              ) : (
                <>
                  <Mail className="w-4 h-4" />
                  <span>Send Password Reset Instructions</span>
                  <ArrowRight className="w-3.5 h-3.5 opacity-70" />
                </>
              )}
            </button>
          </form>

          {/* Navigation for Forgot Password mode */}
          {mode === 'forgot_password' && (
            <div className="mt-5 pt-4 border-t border-slate-800/80 text-center">
              <button
                type="button"
                onClick={() => switchMode('signin')}
                className="inline-flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 transition-colors font-medium cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Return to Sign In</span>
              </button>
            </div>
          )}

          {/* Switch to Sign Up from Sign In prompt */}
          {mode === 'signin' && (
            <p className="mt-5 text-center text-xs text-slate-400">
              Don't have an operator account?{' '}
              <button
                type="button"
                onClick={() => switchMode('signup')}
                className="text-indigo-400 hover:text-indigo-300 font-medium transition-colors cursor-pointer"
              >
                Sign up here
              </button>
            </p>
          )}

          {/* Switch to Sign In from Sign Up prompt */}
          {mode === 'signup' && (
            <p className="mt-5 text-center text-xs text-slate-400">
              Already have an account?{' '}
              <button
                type="button"
                onClick={() => switchMode('signin')}
                className="text-indigo-400 hover:text-indigo-300 font-medium transition-colors cursor-pointer"
              >
                Sign in
              </button>
            </p>
          )}

          {/* Designated Administrator Quick Operator Launch */}
          <div className="mt-5 pt-4 border-t border-slate-800/80">
            <button
              type="button"
              onClick={handleQuickLogin}
              disabled={submitting}
              className="w-full py-2.5 px-3.5 rounded-xl bg-slate-950/80 hover:bg-slate-800/80 border border-slate-800 hover:border-indigo-500/40 text-slate-300 hover:text-white font-medium text-xs flex items-center justify-between transition-all shadow-sm cursor-pointer disabled:opacity-50 group"
            >
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-lg bg-indigo-500/10 flex items-center justify-center border border-indigo-500/20 text-indigo-400 group-hover:text-indigo-300">
                  <UserCheck className="w-3.5 h-3.5" />
                </div>
                <div className="text-left">
                  <span className="block text-[11px] font-semibold text-slate-200">
                    Administrator One-Click Sign In
                  </span>
                  <span className="block text-[10px] text-slate-400 font-mono">
                    armanahz2026@gmail.com
                  </span>
                </div>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 group-hover:bg-indigo-500/20">
                Instant Access &rarr;
              </span>
            </button>
          </div>
        </div>

        {/* Footer info */}
        <div className="mt-6 text-center space-y-1">
          <p className="text-[11px] text-slate-500 font-mono">
            REA Studio &bull; Cryptographic Provenance &amp; Truth Ledger
          </p>
          <p className="text-[10px] text-slate-600">
            Cloud Firestore &bull; Firebase Auth &bull; Anti-SSRF Network Boundary
          </p>
        </div>
      </div>
    </div>
  );
};
