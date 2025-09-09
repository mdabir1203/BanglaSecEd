import { useState, useEffect } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

export const useAuth = () => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Set up auth state listener FIRST
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, session) => {
        setSession(session);
        setUser(session?.user ?? null);
        setLoading(false);
      }
    );

    // THEN check for existing session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    });

    return () => subscription.unsubscribe();
  }, []);

  const signUp = async (email: string, password: string, displayName?: string) => {
    try {
      const redirectUrl = `${window.location.origin}/`;
      
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
          emailRedirectTo: redirectUrl,
          data: {
            display_name: displayName
          }
        }
      });

      if (error) {
        toast.error(error.message);
        return { error };
      }

      if (data.user && !data.session) {
        toast.success('Please check your email to verify your account');
      }

      return { data };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'An error occurred during signup';
      toast.error(message);
      return { error: { message } };
    }
  };

  const signIn = async (email: string, password: string) => {
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password
      });

      if (error) {
        toast.error(error.message);
        return { error };
      }

      toast.success('Welcome back!');
      return { data };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'An error occurred during signin';
      toast.error(message);
      return { error: { message } };
    }
  };

  const signOut = async () => {
    try {
      const { error } = await supabase.auth.signOut();
      if (error) {
        toast.error(error.message);
        return { error };
      }
      toast.success('Signed out successfully');
      return {};
    } catch (error) {
      const message = error instanceof Error ? error.message : 'An error occurred during signout';
      toast.error(message);
      return { error: { message } };
    }
  };

  return {
    user,
    session,
    loading,
    signUp,
    signIn,
    signOut,
    isAuthenticated: !!user
  };
};