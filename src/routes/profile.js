const express = require('express');
const router = express.Router();

// Helper function to fetch profiles
async function fetchProfiles(token) {
  try {
    const [userResponse, companyResponse] = await Promise.all([
      fetch(`${process.env.LOUPE_API_BASE_URL}/api/UserProfiles`, {
        headers: { 'Authorization': `Bearer ${token}` }
      }),
      fetch(`${process.env.LOUPE_API_BASE_URL}/index.php?route=atelier_enterprise_api/company/init`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })
    ]);

    if (!userResponse.ok || !companyResponse.ok) {
      // If either request fails with 401, return that status
      if (userResponse.status === 401 || companyResponse.status === 401) {
        throw { status: 401, message: 'Unauthorized' };
      }
      throw new Error('Failed to fetch profiles');
    }

    const userProfile = await userResponse.json();
    const companyProfile = await companyResponse.json();

    return {
      userProfile: userProfile.value,
      companyProfile
    };
  } catch (error) {
    if (error.status === 401) {
      throw error;
    }
    console.error('Error fetching profiles:', error);
    return { userProfile: {}, companyProfile: {} };
  }
}

// Get user profile
router.get('/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const { userProfile } = await fetchProfiles(token);
    res.json(userProfile);
  } catch (error) {
    if (error.status === 401) {
      res.status(401).json({ error: 'Unauthorized' });
    } else {
      res.status(500).json({ error: 'Failed to fetch user profile' });
    }
  }
});

// Get company profile
router.get('/company', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const { companyProfile } = await fetchProfiles(token);
    res.json(companyProfile);
  } catch (error) {
    if (error.status === 401) {
      res.status(401).json({ error: 'Unauthorized' });
    } else {
      res.status(500).json({ error: 'Failed to fetch company profile' });
    }
  }
});

module.exports = router; 