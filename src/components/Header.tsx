import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Shield, LogOut, User } from 'lucide-react';
import { Link } from 'react-router-dom';

export const Header = () => {
  const { user, signOut, isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return null; // Don't show header when not authenticated
  }

  const handleSignOut = async () => {
    await signOut();
  };

  return (
    <Card className="bg-card/80 backdrop-blur-sm border-primary/30 mb-6">
      <div className="flex items-center justify-between p-4">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-primary cyber-glow" />
          <div>
            <h1 className="text-2xl font-bold bg-gradient-primary bg-clip-text text-transparent">
              SubEnum Pro
            </h1>
            <p className="text-xs text-muted-foreground">Secure Reconnaissance Platform</p>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          <Badge variant="outline" className="border-primary/50 text-primary">
            <User className="h-3 w-3 mr-1" />
            {user?.email?.split('@')[0] || 'Security Analyst'}
          </Badge>
          
          <Button 
            variant="outline" 
            size="sm" 
            onClick={handleSignOut}
            className="border-primary/50 hover:bg-primary/10"
          >
            <LogOut className="h-4 w-4 mr-2" />
            Sign Out
          </Button>
        </div>
      </div>
    </Card>
  );
};