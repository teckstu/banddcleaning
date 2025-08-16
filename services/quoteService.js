const { Quote, Admin } = require('../models/database');
const { Op } = require('sequelize');

class QuoteService {
  // Create new quote
  static async createQuote(quoteData, requestInfo = {}) {
    try {
      const quote = await Quote.create({
        name: quoteData.name?.trim(),
        email: quoteData.email?.trim().toLowerCase(),
        phone: quoteData.phone?.trim() || '',
        service_type: quoteData.serviceType, // Fix field mapping
        message: quoteData.message?.trim() || null,
        preferred_date: quoteData.preferredDate || null,
        ip_address: requestInfo.ip || null,
        user_agent: requestInfo.userAgent || null,
        status: 'new'
      });

      return quote;
    } catch (error) {
      console.error('Database error:', error);
      throw new Error(`Failed to create quote: ${error.message}`);
    }
  }

  // Get all quotes with pagination and filtering
  static async getQuotes(options = {}) {
    try {
      const {
        page = 1,
        limit = 50,
        status,
        serviceType,
        search,
        startDate,
        endDate,
        sortBy = 'created_at',
        sortOrder = 'DESC'
      } = options;

      const offset = (page - 1) * limit;
      const where = {};

      // Filter by status
      if (status) {
        where.status = status;
      }

      // Filter by service type
      if (serviceType) {
        where.service_type = serviceType;
      }

      // Search in name, email, or message
      if (search) {
        where[Op.or] = [
          { name: { [Op.like]: `%${search}%` } },
          { email: { [Op.like]: `%${search}%` } },
          { message: { [Op.like]: `%${search}%` } }
        ];
      }

      // Date range filter
      if (startDate || endDate) {
        where.created_at = {};
        if (startDate) where.created_at[Op.gte] = new Date(startDate);
        if (endDate) where.created_at[Op.lte] = new Date(endDate);
      }

      const result = await Quote.findAndCountAll({
        where,
        order: [[sortBy, sortOrder]],
        limit: parseInt(limit),
        offset: parseInt(offset)
      });

      return {
        quotes: result.rows,
        total: result.count,
        totalPages: Math.ceil(result.count / limit),
        currentPage: parseInt(page),
        hasNext: page * limit < result.count,
        hasPrev: page > 1
      };

    } catch (error) {
      throw new Error(`Failed to fetch quotes: ${error.message}`);
    }
  }

  // Get single quote by ID
  static async getQuoteById(id) {
    try {
      const quote = await Quote.findByPk(id);
      if (!quote) {
        throw new Error('Quote not found');
      }
      return quote;
    } catch (error) {
      throw new Error(`Failed to fetch quote: ${error.message}`);
    }
  }

  // Update quote status and notes
  static async updateQuote(id, updates) {
    try {
      const quote = await Quote.findByPk(id);
      if (!quote) {
        throw new Error('Quote not found');
      }

      await quote.update(updates);
      return quote;
    } catch (error) {
      throw new Error(`Failed to update quote: ${error.message}`);
    }
  }

  // Delete quote
  static async deleteQuote(id) {
    try {
      const quote = await Quote.findByPk(id);
      if (!quote) {
        throw new Error('Quote not found');
      }

      await quote.destroy();
      return true;
    } catch (error) {
      throw new Error(`Failed to delete quote: ${error.message}`);
    }
  }

  // Get quote statistics
  static async getQuoteStats() {
    try {
      const total = await Quote.count();
      const newQuotes = await Quote.count({ where: { status: 'new' } });
      const thisMonth = await Quote.count({
        where: {
          created_at: {
            [Op.gte]: new Date(new Date().getFullYear(), new Date().getMonth(), 1)
          }
        }
      });

      const statusCounts = await Quote.findAll({
        attributes: [
          'status',
          [Quote.sequelize.fn('COUNT', Quote.sequelize.col('status')), 'count']
        ],
        group: ['status']
      });

      const serviceTypeCounts = await Quote.findAll({
        attributes: [
          'service_type',
          [Quote.sequelize.fn('COUNT', Quote.sequelize.col('service_type')), 'count']
        ],
        group: ['service_type']
      });

      return {
        total,
        newQuotes,
        thisMonth,
        statusBreakdown: statusCounts.reduce((acc, item) => {
          acc[item.status] = parseInt(item.dataValues.count);
          return acc;
        }, {}),
        serviceTypeBreakdown: serviceTypeCounts.reduce((acc, item) => {
          acc[item.service_type] = parseInt(item.dataValues.count);
          return acc;
        }, {})
      };

    } catch (error) {
      throw new Error(`Failed to fetch quote statistics: ${error.message}`);
    }
  }
}

module.exports = QuoteService;