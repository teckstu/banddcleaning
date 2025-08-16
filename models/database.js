const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');

// Initialize SQLite database
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, '..', 'database.sqlite'),
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
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
    // Test connection
    await sequelize.authenticate();
    console.log('✅ Database connection established');

    // Sync models (create tables)
    await sequelize.sync({ alter: true });
    console.log('✅ Database models synchronized');

    // Create default admin if none exists
    const adminCount = await Admin.count();
    if (adminCount === 0) {
      const bcrypt = require('bcryptjs');
      const defaultPassword = 'admin123'; // Change this!
      const passwordHash = await bcrypt.hash(defaultPassword, 12);

      await Admin.create({
        email: 'bandcleaningco@gmail.com',
        password_hash: passwordHash,
        name: 'Admin User',
        role: 'admin'
      });

      console.log('✅ Default admin user created');
      console.log('📧 Email: bandcleaningco@gmail.com');
      console.log('🔑 Password: admin123 (CHANGE THIS!)');
    }

    return { sequelize, Quote, Admin };

  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    throw error;
  }
};

module.exports = {
  sequelize,
  Quote,
  Admin,
  initializeDatabase
};