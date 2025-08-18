import { Suspense, lazy } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./hooks/useAuth";
import Layout from "./components/layout/Layout";
import ProtectedRoute from "./components/auth/ProtectedRoute";
import LoadingScreen from "./components/ui/LoadingScreen";
import VMConsole from "./pages/VMConsole";

// Lazy load pages for better performance
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Login = lazy(() => import("./pages/Login"));
const CreateVM = lazy(() => import("./pages/CreateVM"));
const VMDetails = lazy(() => import("./pages/VMDetails"));
const Settings = lazy(() => import("./pages/Settings"));
const Hypervisors = lazy(() => import("./pages/Hypervisors"));
const NotFound = lazy(() => import("./pages/NotFound"));
const Profile = lazy(() => import("./pages/Profile"));
const HypervisorDetails = lazy(() => import("./pages/HypervisorDetails"));
const Stats = lazy(() => import("./pages/Stats"));
const PreferencesPage = lazy(() => import("./pages/PreferencesPage"));


function App() {
  const { isAuthenticated, user } = useAuth(); // Destructure user as well

  return (
    <Suspense fallback={<LoadingScreen />}>
      <Routes>
        <Route
          path="/login"
          element={!isAuthenticated ? <Login /> : <Navigate to="/" replace />}
        />

        <Route element={<Layout />}>
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />

          <Route
            path="/create-vm"
            element={
              <ProtectedRoute>
                
                {(user?.role === 'admin' || user?.role === 'user') ? (
                  <CreateVM />
                ) : (
                  <Navigate to="/" replace /> // Redirect viewers or other roles
                )}
              </ProtectedRoute>
            }
          />

          <Route
            path="/vm/:id"
            element={
              <ProtectedRoute>
                <VMDetails />
              </ProtectedRoute>
            }
          />

          <Route
            path="/hypervisors"
            element={
              <ProtectedRoute>
                <Hypervisors />
              </ProtectedRoute>
            }
          />

          <Route
            path="/settings"
            element={
              <ProtectedRoute> 
                {(user?.role === 'admin' || user?.role === 'user') ? (
                  <Settings />
                ) : (
                  <Navigate to="/" replace /> // Redirect viewers or other non-permitted roles
                )}
              </ProtectedRoute>
            }
          />

          <Route
            path="/profile"
            element={
              <ProtectedRoute>
                <Profile />
              </ProtectedRoute>
            }
          />
          <Route
            path="/hypervisors/:id"
            element={
              <ProtectedRoute>
                <HypervisorDetails />
              </ProtectedRoute>
            }
          />
          <Route
            path="/stats"
            element={
              <ProtectedRoute>
                <Stats />
              </ProtectedRoute>
            }
          />
          <Route
            path="/preferences"
            element={
              <ProtectedRoute>
                <PreferencesPage />
              </ProtectedRoute>
            }
          />
        </Route>

         {/* Ruta para la consola en ventana aparte */}
         <Route
          path="/console/:id"
          element={
            <ProtectedRoute>
              <VMConsole />
            </ProtectedRoute>
          }
        />

        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
  );
}

export default App;
