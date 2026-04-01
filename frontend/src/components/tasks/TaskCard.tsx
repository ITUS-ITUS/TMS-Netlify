import { useAuth } from '../../contexts/AuthContext';

type TaskStatus = 'TODO' | 'IN_PROGRESS' | 'COMPLETED';
type Priority = 'LOW' | 'MEDIUM' | 'HIGH';

interface Task {
  id: number;
  title: string;
  description?: string;
  status: TaskStatus;
  priority: Priority;
  userId: number;
  user: { id: number; username: string; email: string };
  assignedTo?: number;
  assignee?: { id: number; username: string; email: string };
  dueDate?: string;
}

interface TaskCardProps {
  task: Task;
  onEdit: (task: Task) => void;
  onDelete: (task: Task) => void;
  onStatusChange: (task: Task, status: string) => void;
}

export default function TaskCard({ task, onEdit, onDelete, onStatusChange }: TaskCardProps) {
  const { user, hasPermission, isAdmin, isManager } = useAuth();

  const isOwner = task.userId === user?.id;
  const isAssignee = task.assignedTo === user?.id;
  // Admin and Manager can edit all tasks, others can edit their own
  const canEdit = isAdmin || isManager || hasPermission('edit_task') && (isOwner || isAssignee);
  // Admin and Manager can delete all, others can delete own
  const canDelete = isAdmin || isManager || (hasPermission('delete_task') && isOwner);

  const statusColors = {
    TODO: 'bg-gray-100 text-gray-700',
    IN_PROGRESS: 'bg-blue-100 text-blue-700',
    COMPLETED: 'bg-green-100 text-green-700'
  };

  const statusLabels = {
    TODO: 'To Do',
    IN_PROGRESS: 'In Progress',
    COMPLETED: 'Completed'
  };

  const priorityColors = {
    LOW: 'bg-slate-100 text-slate-600',
    MEDIUM: 'bg-yellow-100 text-yellow-700',
    HIGH: 'bg-red-100 text-red-700'
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return null;
    return new Date(dateString).toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric',
      year: 'numeric'
    });
  };

  const isOverdue = task.dueDate && new Date(task.dueDate) < new Date() && task.status !== 'COMPLETED';

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <h3 className="font-medium text-gray-900 truncate">{task.title}</h3>
          {task.description && (
            <p className="text-sm text-gray-600 mt-1 line-clamp-2">{task.description}</p>
          )}
        </div>
        
        <div className="flex items-center space-x-1">
          {canEdit && (
            <button
              onClick={() => onEdit(task)}
              className="p-1.5 text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 rounded transition-colors"
              title="Edit"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
            </button>
          )}
          {canDelete && (
            <button
              onClick={() => onDelete(task)}
              className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded transition-colors"
              title="Delete"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          )}
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${statusColors[task.status]}`}>
          {statusLabels[task.status]}
        </span>
        <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${priorityColors[task.priority]}`}>
          {task.priority}
        </span>
        {task.dueDate && (
          <span className={`px-2 py-0.5 text-xs rounded-full ${isOverdue ? 'bg-red-100 text-red-700' : 'bg-gray-100 text-gray-600'}`}>
            Due: {formatDate(task.dueDate)}
          </span>
        )}
      </div>

      <div className="mt-3 pt-3 border-t border-gray-100 flex items-center justify-between">
        <div className="text-xs text-gray-500">
          <span>By: {task.user.username}</span>
          {task.assignee && (
            <span className="ml-2">• Assigned: {task.assignee.username}</span>
          )}
        </div>

        {canEdit && task.status !== 'COMPLETED' && (
          <select
            value={task.status}
            onChange={(e) => onStatusChange(task, e.target.value)}
            className="text-xs px-2 py-1 border border-gray-200 rounded focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500"
          >
            <option value="TODO">To Do</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="COMPLETED">Completed</option>
          </select>
        )}
      </div>
    </div>
  );
}
