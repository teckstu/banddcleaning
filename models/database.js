const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');
const bcrypt = require('bcryptjs');

// Initialize SQLite database
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, '..', 'database.sqlite'),
  logging: false,
  define: {
    timestamps: true,
    underscored: true
  }
});

// Quote Model
const Quote = sequelize.define('Quote', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: true,
      len: [1, 100]
    }
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      isEmail: true,
      len: [5, 255]
    }
  },
  phone: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: true,
      len: [8, 20]
    }
  },
  service_type: {
    type: DataTypes.ENUM,
    values: [
      'End of Lease Cleaning',
      'Regular Cleaning',
      'Deep Cleaning',
      'Office Cleaning',
      'Carpet Cleaning',
      'Window Cleaning',
      'Other'
    ],
    allowNull: false
  },
  message: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  preferred_date: {
    type: DataTypes.DATEONLY,
    allowNull: true
  },
  status: {
    type: DataTypes.ENUM,
    values: ['new', 'contacted', 'quoted', 'accepted', 'rejected', 'completed'],
    defaultValue: 'new',
    allowNull: false
  },
  quote_amount: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: true
  },
  notes: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  ip_address: {
    type: DataTypes.STRING,
    allowNull: true
  },
  user_agent: {
    type: DataTypes.TEXT,
    allowNull: true
  }
}, {
  tableName: 'quotes',
  indexes: [
    {
      fields: ['email']
    },
    {
      fields: ['status']
    },
    {
      fields: ['created_at']
    },
    {
      fields: ['service_type']
    }
  ]
});

// Admin Model (replace admin.json)
const Admin = sequelize.define('Admin', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true
    }
  },
  password_hash: {
    type: DataTypes.STRING,
    allowNull: false
  },
  name: {
    type: DataTypes.STRING,
    allowNull: true
  },
  role: {
    type: DataTypes.ENUM,
    values: ['admin', 'manager', 'staff'],
    defaultValue: 'admin'
  },
  is_active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  last_login: {
    type: DataTypes.DATE,
    allowNull: true
  },
  login_attempts: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  locked_until: {
    type: DataTypes.DATE,
    allowNull: true
  }
}, {
  tableName: 'admins',
  indexes: [
    {
      fields: ['email'],
      unique: true
    }
  ]
});

// Initialize database
const initializeDatabase = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connection established');
    
    // Sync models with database
    await sequelize.sync({
      alter: process.env.DB_ALTER_TABLES === 'true',
      force: process.env.DB_FORCE_SYNC === 'true'
    });
    
    // Create default admin if it doesn't exist
    const adminEmail = process.env.DEFAULT_ADMIN_EMAIL;
    const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD;
    const adminName = process.env.DEFAULT_ADMIN_NAME;

    if (!adminEmail || !adminPassword) {
      console.error('❌ Missing DEFAULT_ADMIN_EMAIL or DEFAULT_ADMIN_PASSWORD in environment');
      return false;
    }

    const existingAdmin = await Admin.findOne({ where: { email: adminEmail } });
    
    if (!existingAdmin) {
      console.log('Creating default admin account...');
      const passwordHash = await bcrypt.hash(adminPassword, parseInt(process.env.BCRYPT_ROUNDS || '12'));
      
      await Admin.create({
        email: adminEmail,
        password_hash: passwordHash,
        name: adminName || 'Administrator',
        role: 'admin',
        is_active: true
      });
      
      console.log('✅ Default admin account created');
    }
    
    console.log('✅ Database models synchronized');
    return true;
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    throw error;
  }
};

module.exports = {
  sequelize,
  Quote,
  Admin,
  initializeDatabase
};