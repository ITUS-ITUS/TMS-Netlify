import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('🔧 Setting up database...');

  // Create roles
  const adminRole = await prisma.role.upsert({
    where: { name: 'admin' },
    update: {},
    create: { name: 'admin', description: 'Full system access' }
  });

  const managerRole = await prisma.role.upsert({
    where: { name: 'manager' },
    update: {},
    create: { name: 'manager', description: 'Can manage tasks and view users' }
  });

  const userRole = await prisma.role.upsert({
    where: { name: 'user' },
    update: {},
    create: { name: 'user', description: 'Basic task operations' }
  });

  console.log('✅ Roles created');

  // Create permissions
  const permissions = [
    { name: 'create_task', description: 'Create new tasks' },
    { name: 'read_task', description: 'View tasks' },
    { name: 'edit_task', description: 'Edit existing tasks' },
    { name: 'delete_task', description: 'Delete tasks' },
    { name: 'read_users', description: 'View user list' },
    { name: 'manage_users', description: 'Create, edit, delete users' },
    { name: 'assign_task', description: 'Assign tasks to users' }
  ];

  for (const perm of permissions) {
    await prisma.permission.upsert({
      where: { name: perm.name },
      update: {},
      create: perm
    });
  }

  console.log('✅ Permissions created');

  // Get all permission IDs
  const allPermissions = await prisma.permission.findMany();
  const permissionMap = Object.fromEntries(allPermissions.map(p => [p.name, p.id]));

  // Admin gets all permissions
  for (const perm of allPermissions) {
    await prisma.rolePermission.upsert({
      where: { roleId_permissionId: { roleId: adminRole.id, permissionId: perm.id } },
      update: {},
      create: { roleId: adminRole.id, permissionId: perm.id }
    });
  }

  // Manager permissions
  const managerPerms = ['create_task', 'read_task', 'edit_task', 'delete_task', 'read_users', 'assign_task'];
  for (const permName of managerPerms) {
    await prisma.rolePermission.upsert({
      where: { roleId_permissionId: { roleId: managerRole.id, permissionId: permissionMap[permName] } },
      update: {},
      create: { roleId: managerRole.id, permissionId: permissionMap[permName] }
    });
  }

  // User permissions
  const userPerms = ['create_task', 'read_task', 'edit_task'];
  for (const permName of userPerms) {
    await prisma.rolePermission.upsert({
      where: { roleId_permissionId: { roleId: userRole.id, permissionId: permissionMap[permName] } },
      update: {},
      create: { roleId: userRole.id, permissionId: permissionMap[permName] }
    });
  }

  console.log('✅ Role permissions assigned');

  // Create demo users (password: admin123)
  const hashedPassword = await bcrypt.hash('admin123', 10);

  await prisma.user.upsert({
    where: { email: 'admin@admin.com' },
    update: {},
    create: {
      email: 'admin@admin.com',
      username: 'admin',
      password: hashedPassword,
      roleId: adminRole.id
    }
  });

  await prisma.user.upsert({
    where: { email: 'manager@example.com' },
    update: {},
    create: {
      email: 'manager@example.com',
      username: 'manager',
      password: hashedPassword,
      roleId: managerRole.id
    }
  });

  await prisma.user.upsert({
    where: { email: 'user@example.com' },
    update: {},
    create: {
      email: 'user@example.com',
      username: 'user',
      password: hashedPassword,
      roleId: userRole.id
    }
  });

  console.log('✅ Demo users created');

  // Get created users for task assignment
  const adminUser = await prisma.user.findUnique({ where: { email: 'admin@admin.com' } });
  const managerUser = await prisma.user.findUnique({ where: { email: 'manager@example.com' } });
  const regularUser = await prisma.user.findUnique({ where: { email: 'user@example.com' } });

  // Create demo tasks
  const demoTasks = [
    {
      title: 'Setup Project Infrastructure',
      description: 'Configure development environment, CI/CD pipeline, and deployment scripts',
      status: 'COMPLETED',
      priority: 'HIGH',
      userId: adminUser!.id,
      assignedTo: adminUser!.id
    },
    {
      title: 'Design Database Schema',
      description: 'Create ERD and define all database tables, relationships, and indexes',
      status: 'COMPLETED',
      priority: 'HIGH',
      userId: adminUser!.id,
      assignedTo: managerUser!.id
    },
    {
      title: 'Implement User Authentication',
      description: 'Add JWT-based authentication with login, register, and token refresh',
      status: 'IN_PROGRESS',
      priority: 'HIGH',
      userId: managerUser!.id,
      assignedTo: regularUser!.id
    },
    {
      title: 'Create Task Management API',
      description: 'Build CRUD endpoints for tasks with proper validation and error handling',
      status: 'IN_PROGRESS',
      priority: 'MEDIUM',
      userId: managerUser!.id,
      assignedTo: managerUser!.id
    },
    {
      title: 'Build Dashboard UI',
      description: 'Design and implement the main dashboard with task statistics and filters',
      status: 'TODO',
      priority: 'MEDIUM',
      userId: adminUser!.id,
      assignedTo: regularUser!.id
    },
    {
      title: 'Add Role-Based Access Control',
      description: 'Implement RBAC system with admin, manager, and user roles',
      status: 'TODO',
      priority: 'HIGH',
      userId: adminUser!.id,
      assignedTo: managerUser!.id
    },
    {
      title: 'Write Unit Tests',
      description: 'Create comprehensive test suite for all API endpoints',
      status: 'TODO',
      priority: 'LOW',
      userId: managerUser!.id,
      assignedTo: regularUser!.id
    },
    {
      title: 'Documentation',
      description: 'Write API documentation and user guide for the application',
      status: 'TODO',
      priority: 'LOW',
      userId: regularUser!.id,
      assignedTo: regularUser!.id
    }
  ];

  for (const task of demoTasks) {
    await prisma.task.create({ data: task });
  }

  console.log('✅ Demo tasks created');
  console.log('');
  console.log('📋 Demo Credentials:');
  console.log('   Admin:   admin@admin.com / admin123');
  console.log('   Manager: manager@example.com / admin123');
  console.log('   User:    user@example.com / admin123');
  console.log('');
  console.log('🎉 Database setup complete!');
}

main()
  .catch((e) => {
    console.error('❌ Database setup failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
