import { useLocation } from "react-router-dom";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Shield, Home } from "lucide-react";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error("404 Error: User attempted to access non-existent route:", location.pathname);
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="text-center space-y-6">
        <Shield className="h-24 w-24 text-primary mx-auto cyber-glow" />
        <div className="space-y-2">
          <h1 className="text-6xl font-bold bg-gradient-primary bg-clip-text text-transparent">404</h1>
          <h2 className="text-2xl font-semibold text-primary">Access Denied</h2>
          <p className="text-lg text-muted-foreground max-w-md mx-auto">
            The requested resource could not be located in the security perimeter.
          </p>
        </div>
        <Button variant="cyber" asChild className="mt-6">
          <a href="/">
            <Home className="h-4 w-4 mr-2" />
            Return to Command Center
          </a>
        </Button>
      </div>
    </div>
  );
};

export default NotFound;
