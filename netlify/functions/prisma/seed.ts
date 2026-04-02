import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

const permissions = [
  { name: 'users:create', description: 'Create new users' },
  { name: 'users:read', description: 'View all users' },
  { name: 'users:update', description: 'Update any user' },
  { name: 'users:delete', description: 'Delete users' },
  { name: 'tasks:create', description: 'Create tasks' },
  { name: 'tasks:read:all', description: 'View all tasks' },
  { name: 'tasks:read:own', description: 'View own tasks' },
  { name: 'tasks:update:all', description: 'Update any task' },
  { name: 'tasks:update:own', description: 'Update own tasks' },
  { name: 'tasks:delete:all', description: 'Delete any task' },
  { name: 'tasks:delete:own', description: 'Delete own tasks' },
  { name: 'tasks:assign', description: 'Assign tasks to users' },
  { name: 'roles:manage', description: 'Manage roles and permissions' },
];

const roles = [
  {
    name: 'Admin',
    description: 'Full system access - manage users, all tasks, roles',
    permissions: [
      'users:create', 'users:read', 'users:update', 'users:delete',
      'tasks:create', 'tasks:read:all', 'tasks:read:own',
      'tasks:update:all', 'tasks:update:own',
      'tasks:delete:all', 'tasks:delete:own',
      'tasks:assign', 'roles:manage'
    ]
  },
  {
    name: 'Manager',
    description: 'Can view all tasks, assign tasks, manage team tasks',
    permissions: [
      'users:read',
      'tasks:create', 'tasks:read:all', 'tasks:read:own',
      'tasks:update:all', 'tasks:update:own',
      'tasks:delete:own',
      'tasks:assign'
    ]
  },
  {
    name: 'User',
    description: 'Can only manage their own tasks',
    permissions: [
      'tasks:create', 'tasks:read:own',
      'tasks:update:own', 'tasks:delete:own'
    ]
  }
];

// Demo users
const demoUsers = [
  { username: 'admin', email: 'admin@admin.com', password: 'admin123', role: 'Admin' },
  { username: 'manager', email: 'manager@example.com', password: 'manager123', role: 'Manager' },
  { username: 'user', email: 'user@example.com', password: 'user123', role: 'User' },
];

// Demo tasks
const demoTasks = [
  { title: 'Setup project structure', description: 'Initialize the project with React and Node.js', status: 'COMPLETED', priority: 'HIGH' },
  { title: 'Design database schema', description: 'Create ERD and define tables for users and tasks', status: 'COMPLETED', priority: 'HIGH' },
  { title: 'Implement user authentication', description: 'Add JWT-based login and registration', status: 'COMPLETED', priority: 'HIGH' },
  { title: 'Create REST API endpoints', description: 'Build CRUD APIs for tasks management', status: 'IN_PROGRESS', priority: 'HIGH' },
  { title: 'Build login page UI', description: 'Create responsive login form with validation', status: 'COMPLETED', priority: 'MEDIUM' },
  { title: 'Build dashboard UI', description: 'Create task list view with filters', status: 'IN_PROGRESS', priority: 'MEDIUM' },
  { title: 'Add task filtering', description: 'Implement filter by status dropdown', status: 'TODO', priority: 'MEDIUM' },
  { title: 'Write unit tests', description: 'Add tests for API endpoints', status: 'TODO', priority: 'LOW' },
  { title: 'Deploy to production', description: 'Deploy frontend to Netlify and backend to server', status: 'TODO', priority: 'HIGH' },
  { title: 'Create documentation', description: 'Write API documentation and README', status: 'TODO', priority: 'LOW' },
  { title: 'Code review', description: 'Review code for best practices', status: 'IN_PROGRESS', priority: 'MEDIUM' },
  { title: 'Bug fixes', description: 'Fix reported bugs from testing', status: 'TODO', priority: 'HIGH' },
];

async function main() {
  console.log('🌱 Seeding database...');

  // Clear existing data
  console.log('Clearing existing data...');
  await prisma.task.deleteMany({});
  await prisma.rolePermission.deleteMany({});
  await prisma.user.deleteMany({});
  await prisma.permission.deleteMany({});
  await prisma.role.deleteMany({});

  // Create permissions
  console.log('Creating permissions...');
  for (const perm of permissions) {
    await prisma.permission.create({ data: perm });
  }

  // Create roles with permissions
  console.log('Creating roles...');
  for (const role of roles) {
    const createdRole = await prisma.role.create({
      data: {
        name: role.name,
        description: role.description
      }
    });

    // Get permission IDs
    const permissionRecords = await prisma.permission.findMany({
      where: { name: { in: role.permissions } }
    });

    // Create role permissions
    for (const perm of permissionRecords) {
      await prisma.rolePermission.create({
        data: {
          roleId: createdRole.id,
          permissionId: perm.id
        }
      });
    }

    console.log(`  ✓ Created role: ${role.name} with ${role.permissions.length} permissions`);
  }

  // Create demo users
  console.log('Creating demo users...');
  const createdUsers: { id: number; username: string; role: string }[] = [];
  
  for (const user of demoUsers) {
    const role = await prisma.role.findUnique({ where: { name: user.role } });
    if (role) {
      const hashedPassword = await bcrypt.hash(user.password, 10);
      const created = await prisma.user.create({
        data: {
          email: user.email,
          username: user.username,
          password: hashedPassword,
          roleId: role.id
        }
      });
      createdUsers.push({ id: created.id, username: created.username, role: user.role });
      console.log(`  ✓ ${user.role}: ${user.email} / ${user.password}`);
    }
  }

  // Create demo tasks
  console.log('Creating demo tasks...');
  
  for (let i = 0; i < demoTasks.length; i++) {
    const task = demoTasks[i];
    const owner = createdUsers[i % createdUsers.length];
    const assignee = createdUsers[(i + 1) % createdUsers.length];
    
    await prisma.task.create({
      data: {
        title: task.title,
        description: task.description,
        status: task.status,
        priority: task.priority,
        userId: owner.id,
        assignedTo: i % 2 === 0 ? assignee.id : null,
        dueDate: new Date(Date.now() + (i + 1) * 24 * 60 * 60 * 1000)
      }
    });
    console.log(`  ✓ Task: ${task.title} (${task.status})`);
  }

  console.log('');
  console.log('✅ Seeding completed!');
  console.log('');
  console.log('📋 Demo Credentials:');
  console.log('┌─────────────┬─────────────────────────┬─────────────┐');
  console.log('│ Role        │ Email                   │ Password    │');
  console.log('├─────────────┼─────────────────────────┼─────────────┤');
  for (const user of demoUsers) {
    console.log(`│ ${user.role.padEnd(11)} │ ${user.email.padEnd(23)} │ ${user.password.padEnd(11)} │`);
  }
  console.log('└─────────────┴─────────────────────────┴─────────────┘');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
