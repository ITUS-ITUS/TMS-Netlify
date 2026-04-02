import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import api from '../services/api';

interface Role {
  id: number;
  name: string;
  permissions: string[];
}

interface User {
  id: number;
  email: string;
  username: string;
  role: Role;
}

interface AuthResponse {
  message: string;
  token: string;
  user: User;
}

interface ImpersonateResponse extends AuthResponse {
  impersonatedBy?: {
    id: number;
    username: string;
  };
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, username: string, password: string, roleId?: number) => Promise<void>;
  logout: () => void;
  impersonateUser: (userId: number) => Promise<void>;
  hasPermission: (permission: string) => boolean;
  hasAnyPermission: (...permissions: string[]) => boolean;
  isAdmin: boolean;
  isManager: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Validate token and load user on mount
  useEffect(() => {
    const validateAndLoadUser = async () => {
      const storedToken = localStorage.getItem('token');
      
      if (!storedToken) {
        setIsLoading(false);
        return;
      }

      try {
        // Validate token by fetching current user from backend
        const response = await api.get<{ user: User }>('/auth/me', {
          headers: { Authorization: `Bearer ${storedToken}` }
        });
        
        setToken(storedToken);
        setUser(response.data.user);
        // Update stored user with fresh data
        localStorage.setItem('user', JSON.stringify(response.data.user));
      } catch (error) {
        // Token is invalid or expired - clear storage
        console.error('Token validation failed:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setToken(null);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };

    validateAndLoadUser();
  }, []);

  const login = async (email: string, password: string) => {
    const response = await api.post<AuthResponse>('/auth/login', { email, password });
    const { token, user } = response.data;
    
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    setToken(token);
    setUser(user);
  };

  const register = async (email: string, username: string, password: string, roleId?: number) => {
    const response = await api.post<AuthResponse>('/auth/register', { email, username, password, roleId });
    const { token, user } = response.data;
    
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    setToken(token);
    setUser(user);
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken(null);
    setUser(null);
  };

  // Admin impersonation - login as another user
  const impersonateUser = async (userId: number) => {
    const response = await api.post<ImpersonateResponse>(`/auth/impersonate/${userId}`);
    const { token, user } = response.data;
    
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    setToken(token);
    setUser(user);
  };

  const hasPermission = (permission: string): boolean => {
    return user?.role.permissions.includes(permission) ?? false;
  };

  const hasAnyPermission = (...permissions: string[]): boolean => {
    return permissions.some(p => hasPermission(p));
  };

  const isAdmin = user?.role.name?.toLowerCase() === 'admin';
  const isManager = user?.role.name?.toLowerCase() === 'manager';

  return (
    <AuthContext.Provider value={{
      user,
      token,
      isLoading,
      isAuthenticated: !!user && !!token,
      login,
      register,
      logout,
      impersonateUser,
      hasPermission,
      hasAnyPermission,
      isAdmin,
      isManager
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
