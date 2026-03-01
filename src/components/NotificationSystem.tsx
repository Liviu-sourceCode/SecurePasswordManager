import { useState, useEffect, useRef } from 'react';

interface Notification {
  id: string;
  type: 'success' | 'warning' | 'error' | 'info';
  title: string;
  message: string;
  duration?: number;
  persistent?: boolean;
}

interface NotificationSystemProps {
  notifications: Notification[];
  onRemove: (id: string) => void;
}

export function NotificationSystem({ notifications, onRemove }: NotificationSystemProps) {
  useEffect(() => {
    const timers = notifications
      .filter(n => !n.persistent && n.duration !== 0)
      .map(n => setTimeout(() => onRemove(n.id), n.duration || 5000));

    return () => {
      timers.forEach(t => clearTimeout(t));
    };
  }, [notifications, onRemove]);

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'success': return '✅';
      case 'warning': return '⚠️';
      case 'error': return '❌';
      case 'info': return 'ℹ️';
      default: return 'ℹ️';
    }
  };



  if (notifications.length === 0) return null;

  return (
    <div className="notification-container">
      {notifications.map((notification) => (
        <div
          key={notification.id}
          className={`notification-item cursor-pointer ${
            notification.type === 'success' ? 'notification-success' :
            notification.type === 'error' ? 'notification-error' :
            notification.type === 'warning' ? 'notification-warning' :
            'notification-info'
          }`}
          onClick={() => onRemove(notification.id)}
        >
          <div className="notification-layout">
            <span className="notification-icon">
              {getNotificationIcon(notification.type)}
            </span>
            <div className="notification-content">
              <h4 className="notification-title">{notification.title}</h4>
              <p className="notification-message">
                {notification.message}
              </p>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onRemove(notification.id);
              }}
              className="notification-close"
            >
              <svg className="notification-close-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

// Hook for managing notifications
export function useNotifications() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const recentKeysRef = useRef<Map<string, number>>(new Map());

  const addNotification = (notification: Omit<Notification, 'id'>) => {
    const key = `${notification.title}:::${notification.message}`;
    const now = Date.now();
    const TTL = 1500; // 1.5s window to suppress races

    // Suppress duplicates added within a short window
    const last = recentKeysRef.current.get(key);
    if (last && now - last < TTL) {
      const existing = notifications.find(n => n.title === notification.title && n.message === notification.message);
      return existing?.id ?? key;
    }

    recentKeysRef.current.set(key, now);
    const id = crypto.randomUUID();

    setNotifications(prev => {
      // If identical exists in current state, do not add
      if (prev.some(n => n.title === notification.title && n.message === notification.message)) {
        return prev;
      }
      return [...prev, { ...notification, id }];
    });

    // Cleanup old keys
    setTimeout(() => {
      const ts = recentKeysRef.current.get(key);
      if (ts && Date.now() - ts >= TTL) {
        recentKeysRef.current.delete(key);
      }
    }, TTL + 50);

    return id;
  };

  const removeNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };



  return {
    notifications,
    addNotification,
    removeNotification,
    // expose convenience helpers as before
    notifySmartClipboardActive: (service: string) =>
      addNotification({
        type: 'info',
        title: '🧠 Smart Clipboard Active',
        message: `Username copied for ${service}. Paste it, then we'll auto-type the password.`,
        duration: 8000,
        persistent: false
      }),
    notifySmartClipboardSuccess: (service: string) =>
      addNotification({
        type: 'success',
        title: '🎯 Auto-Type Complete',
        message: `Password auto-typed for ${service} successfully.`,
        duration: 4000
      }),
    notifyClipboardInterference: () =>
      addNotification({
        type: 'warning',
        title: '⚠️ Clipboard Interference Detected',
        message: 'Another copy operation interrupted smart clipboard. Please try again.',
        duration: 6000
      }),
  };
}