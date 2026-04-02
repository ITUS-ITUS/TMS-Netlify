import { Handler } from '@netlify/functions';
import express, { Request, Response, NextFunction } from 'express';
import serverless from 'serverless-http';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { body, param, validationResult } from 'express-validator';

// Initialize Prisma Client (reuse connection in serverless)
const prisma = new PrismaClient();

const app = express();

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// JWT Config
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// Generate Token
const generateToken = (userId: number, roleId: number, roleName: string) => {
  return jwt.sign({ userId, roleId, roleName }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN } as jwt.SignOptions);
};

// Auth Middleware
const authenticate = async (req: any, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      include: { role: { include: { permissions: { include: { permission: true } } } } }
    });
    if (!user) return res.status(401).json({ message: 'User not found' });
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Validation Middleware
const validate = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Permission Check
const hasPermission = (permission: string) => {
  return (req: any, res: Response, next: NextFunction) => {
    const userPermissions = req.user?.role?.permissions?.map((p: any) => p.permission.name) || [];
    if (!userPermissions.includes(permission)) {
      return res.status(403).json({ message: 'Permission denied' });
    }
    next();
  };
};

const isAdmin = (req: any, res: Response, next: NextFunction) => {
  if (req.user?.role?.name?.toLowerCase() !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

const isAdminOrManager = (req: any, res: Response, next: NextFunction) => {
  const roleName = req.user?.role?.name?.toLowerCase();
  if (roleName !== 'admin' && roleName !== 'manager') {
    return res.status(403).json({ message: 'Admin or Manager access required' });
  }
  next();
};

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', [
  body('email').isEmail().normalizeEmail(),
  body('username').trim().isLength({ min: 3 }),
  body('password').isLength({ min: 6 })
], validate, async (req: Request, res: Response) => {
  try {
    const { email, username, password, roleId } = req.body;
    const existingUser = await prisma.user.findFirst({
      where: { OR: [{ email }, { username }] }
    });
    if (existingUser) {
      return res.status(400).json({ message: 'Email or username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, username, password: hashedPassword, roleId: roleId || 3 },
      include: { role: { include: { permissions: { include: { permission: true } } } } }
    });
    const token = generateToken(user.id, user.roleId, user.role.name);
    const permissions = user.role.permissions.map(p => p.permission.name);
    res.status(201).json({ 
      token, 
      user: { 
        id: user.id, 
        email: user.email, 
        username: user.username, 
        role: { id: user.role.id, name: user.role.name, permissions } 
      } 
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Error creating user' });
  }
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], validate, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({
      where: { email },
      include: { role: { include: { permissions: { include: { permission: true } } } } }
    });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = generateToken(user.id, user.roleId, user.role.name);
    // Transform permissions to array of strings for frontend
    const permissions = user.role.permissions.map(p => p.permission.name);
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        email: user.email, 
        username: user.username, 
        role: { 
          id: user.role.id, 
          name: user.role.name, 
          permissions 
        } 
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Get Me
app.get('/api/auth/me', authenticate, async (req: any, res: Response) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    include: { role: { include: { permissions: { include: { permission: true } } } } }
  });
  if (!user) return res.status(404).json({ message: 'User not found' });
  // Transform permissions to array of strings for frontend
  const permissions = user.role.permissions.map(p => p.permission.name);
  res.json({ 
    user: { 
      id: user.id, 
      email: user.email, 
      username: user.username, 
      role: { 
        id: user.role.id, 
        name: user.role.name, 
        permissions 
      } 
    } 
  });
});

// Impersonate User (Admin only)
app.post('/api/auth/impersonate/:userId', authenticate, isAdmin, async (req: any, res: Response) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    const targetUser = await prisma.user.findUnique({
      where: { id: targetUserId },
      include: { role: { include: { permissions: { include: { permission: true } } } } }
    });
    if (!targetUser) return res.status(404).json({ message: 'User not found' });
    const token = generateToken(targetUser.id, targetUser.roleId, targetUser.role.name);
    const permissions = targetUser.role.permissions.map(p => p.permission.name);
    res.json({ 
      token, 
      user: { 
        id: targetUser.id, 
        email: targetUser.email, 
        username: targetUser.username, 
        role: { id: targetUser.role.id, name: targetUser.role.name, permissions } 
      } 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error impersonating user' });
  }
});

// ============ TASK ROUTES ============

// Get Tasks
app.get('/api/tasks', authenticate, async (req: any, res: Response) => {
  try {
    const { status } = req.query;
    const roleName = req.user.role.name.toLowerCase();
    const where: any = roleName === 'admin' ? {} : 
      roleName === 'manager' ? {} : 
      { OR: [{ userId: req.user.id }, { assignedTo: req.user.id }] };
    
    // Add status filter if provided
    if (status) {
      where.status = status;
    }
    
    const tasks = await prisma.task.findMany({
      where,
      include: { user: { select: { id: true, username: true, email: true } }, assignee: { select: { id: true, username: true, email: true } } },
      orderBy: { createdAt: 'desc' }
    });
    res.json({ tasks });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching tasks' });
  }
});

// Get Task Stats
app.get('/api/tasks/stats', authenticate, async (req: any, res: Response) => {
  try {
    const roleName = req.user.role.name.toLowerCase();
    const where: any = roleName === 'admin' ? {} : 
      roleName === 'manager' ? {} : 
      { OR: [{ userId: req.user.id }, { assignedTo: req.user.id }] };
    
    const [total, todo, inProgress, completed] = await Promise.all([
      prisma.task.count({ where }),
      prisma.task.count({ where: { ...where, status: 'TODO' } }),
      prisma.task.count({ where: { ...where, status: 'IN_PROGRESS' } }),
      prisma.task.count({ where: { ...where, status: 'COMPLETED' } })
    ]);
    
    res.json({ stats: { total, todo, inProgress, completed } });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching stats' });
  }
});

// Get Assignable Users - Admin can assign to all, Manager can only assign to Users
app.get('/api/tasks/assignable-users', authenticate, isAdminOrManager, async (req: any, res: Response) => {
  try {
    const roleName = req.user.role.name.toLowerCase();
    
    let where: any = {};
    if (roleName === 'manager') {
      // Managers can only assign to Users (not other managers or admins)
      const userRole = await prisma.role.findFirst({ where: { name: { equals: 'User', mode: 'insensitive' } } });
      if (userRole) {
        where.roleId = userRole.id;
      }
    }
    // Admin can assign to all users (no filter)
    
    const users = await prisma.user.findMany({
      where,
      select: { id: true, username: true, email: true, role: { select: { name: true } } }
    });
    
    res.json({ users });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching assignable users' });
  }
});

// Create Task
app.post('/api/tasks', authenticate, [
  body('title').trim().notEmpty(),
  body('status').optional().isIn(['TODO', 'IN_PROGRESS', 'COMPLETED']),
  body('priority').optional().isIn(['LOW', 'MEDIUM', 'HIGH'])
], validate, async (req: any, res: Response) => {
  try {
    const { title, description, status, priority, assignedTo, dueDate } = req.body;
    const roleName = req.user.role.name.toLowerCase();
    
    // Validate assignment permissions
    if (assignedTo) {
      if (roleName === 'user') {
        return res.status(403).json({ message: 'Users cannot assign tasks to others' });
      }
      
      if (roleName === 'manager') {
        // Check if assignee is a User (not admin or manager)
        const assignee = await prisma.user.findUnique({
          where: { id: assignedTo },
          include: { role: true }
        });
        if (assignee && assignee.role.name.toLowerCase() !== 'user') {
          return res.status(403).json({ message: 'Managers can only assign tasks to Users' });
        }
      }
    }
    
    const task = await prisma.task.create({
      data: { title, description, status, priority, userId: req.user.id, assignedTo, dueDate: dueDate ? new Date(dueDate) : null },
      include: { user: { select: { id: true, username: true, email: true } }, assignee: { select: { id: true, username: true, email: true } } }
    });
    res.status(201).json(task);
  } catch (error) {
    res.status(500).json({ message: 'Error creating task' });
  }
});

// Update Task
app.put('/api/tasks/:id', authenticate, [
  param('id').isInt()
], validate, async (req: any, res: Response) => {
  try {
    const taskId = parseInt(req.params.id);
    const task = await prisma.task.findUnique({ where: { id: taskId } });
    if (!task) return res.status(404).json({ message: 'Task not found' });
    
    const roleName = req.user.role.name.toLowerCase();
    
    // Check permission - users can only edit own or assigned tasks
    if (roleName === 'user' && task.userId !== req.user.id && task.assignedTo !== req.user.id) {
      return res.status(403).json({ message: 'Permission denied' });
    }
    
    const { title, description, status, priority, assignedTo, dueDate } = req.body;
    
    // Validate assignment permissions
    if (assignedTo !== undefined && assignedTo !== task.assignedTo) {
      if (roleName === 'user') {
        return res.status(403).json({ message: 'Users cannot assign tasks to others' });
      }
      
      if (roleName === 'manager' && assignedTo !== null) {
        // Check if new assignee is a User (not admin or manager)
        const assignee = await prisma.user.findUnique({
          where: { id: assignedTo },
          include: { role: true }
        });
        if (assignee && assignee.role.name.toLowerCase() !== 'user') {
          return res.status(403).json({ message: 'Managers can only assign tasks to Users' });
        }
      }
    }
    
    const updatedTask = await prisma.task.update({
      where: { id: taskId },
      data: { title, description, status, priority, assignedTo, dueDate: dueDate ? new Date(dueDate) : null },
      include: { user: { select: { id: true, username: true, email: true } }, assignee: { select: { id: true, username: true, email: true } } }
    });
    res.json(updatedTask);
  } catch (error) {
    res.status(500).json({ message: 'Error updating task' });
  }
});

// Delete Task
app.delete('/api/tasks/:id', authenticate, async (req: any, res: Response) => {
  try {
    const taskId = parseInt(req.params.id);
    const task = await prisma.task.findUnique({ where: { id: taskId } });
    if (!task) return res.status(404).json({ message: 'Task not found' });
    
    const roleName = req.user.role.name.toLowerCase();
    
    // Users can only delete own tasks
    if (roleName === 'user' && task.userId !== req.user.id) {
      return res.status(403).json({ message: 'Permission denied' });
    }
    
    await prisma.task.delete({ where: { id: taskId } });
    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting task' });
  }
});

// ============ USER ROUTES ============

// Get Users
app.get('/api/users', authenticate, isAdminOrManager, async (req: any, res: Response) => {
  try {
    const users = await prisma.user.findMany({
      select: { 
        id: true, 
        email: true, 
        username: true, 
        roleId: true, 
        role: true, 
        createdAt: true,
        _count: {
          select: {
            tasks: true,
            assigned: true
          }
        }
      }
    });
    res.json({ users });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching users' });
  }
});

// Get Roles (must come before /api/users/:id)
app.get('/api/users/roles', authenticate, async (req: any, res: Response) => {
  try {
    const roles = await prisma.role.findMany({
      include: { 
        permissions: { include: { permission: true } },
        _count: { select: { users: true } }
      }
    });
    
    // Transform to match frontend expectations
    const transformedRoles = roles.map(role => ({
      id: role.id,
      name: role.name,
      description: role.description,
      permissions: role.permissions.map(p => p.permission.name),
      userCount: role._count.users
    }));
    
    res.json({ roles: transformedRoles });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching roles' });
  }
});

// Create User (Admin only)
app.post('/api/users', authenticate, isAdmin, [
  body('email').isEmail().normalizeEmail(),
  body('username').trim().isLength({ min: 3 }),
  body('password').isLength({ min: 6 }),
  body('roleId').isInt()
], validate, async (req: any, res: Response) => {
  try {
    const { email, username, password, roleId } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, username, password: hashedPassword, roleId },
      include: { role: true }
    });
    res.status(201).json({ id: user.id, email: user.email, username: user.username, role: user.role });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user' });
  }
});

// Update User
app.put('/api/users/:id', authenticate, isAdmin, async (req: any, res: Response) => {
  try {
    const userId = parseInt(req.params.id);
    const { email, username, password, roleId } = req.body;
    const data: any = { email, username, roleId };
    if (password) data.password = await bcrypt.hash(password, 10);
    const user = await prisma.user.update({
      where: { id: userId },
      data,
      include: { role: true }
    });
    res.json({ id: user.id, email: user.email, username: user.username, role: user.role });
  } catch (error) {
    res.status(500).json({ message: 'Error updating user' });
  }
});

// Update User Role
app.put('/api/users/:id/role', authenticate, isAdmin, async (req: any, res: Response) => {
  try {
    const userId = parseInt(req.params.id);
    const { roleId } = req.body;
    const user = await prisma.user.update({
      where: { id: userId },
      data: { roleId },
      include: { role: true }
    });
    res.json({ id: user.id, email: user.email, username: user.username, role: user.role });
  } catch (error) {
    res.status(500).json({ message: 'Error updating user role' });
  }
});

// Delete User
app.delete('/api/users/:id', authenticate, isAdmin, async (req: any, res: Response) => {
  try {
    const userId = parseInt(req.params.id);
    await prisma.task.deleteMany({ where: { userId } });
    await prisma.user.delete({ where: { id: userId } });
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting user' });
  }
});

// Health Check
app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({ message: 'Route not found', path: req.path });
});

// Export handler
export const handler: Handler = serverless(app);
