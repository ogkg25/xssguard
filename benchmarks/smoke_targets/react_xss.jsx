import React from 'react';

// Vulnerable Component
function UserProfile({ bio }) {
  // RULE: React dangerouslySetInnerHTML
  return (
    <div className="profile">
      <h1>User Bio</h1>
      <div dangerouslySetInnerHTML={{ __html: bio }} />
    </div>
  );
}

// Safe Component
function SafeProfile({ bio }) {
  return (
    <div className="profile">
      <h1>User Bio</h1>
      <div>{bio}</div>
    </div>
  );
}
