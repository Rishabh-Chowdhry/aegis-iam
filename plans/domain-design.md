# Domain Design for Our Auth and IAM System

I wanted to document how I structured the domain layer for this authentication and Identity Access Management system. I followed Domain-Driven Design principles, which means the core business logic is completely independent of frameworks or databases. Everything here is pure TypeScript with proper encapsulation.

## Entities

Entities are the core objects in our system - they have identity and can change over time. Two entities with the same properties but different IDs are considered different things.

### The User Entity

Users are the people who log into our system. Each user has an email address (validated and normalized), a hashed password, a list of roles, a status, and belongs to a tenant.

I made sure the User entity enforces its own invariants. You can't create a user without an ID or tenant ID, and the created timestamp can't be after the updated timestamp. The entity also provides business methods like `addRole()`, `removeRole()`, `changeStatus()`, and `updateEmail()`. These methods don't just change values - they also update the `updatedAt` timestamp automatically.

The `hasRole()` method is straightforward but important - it checks if a user has a specific role. And `isActive()` tells you whether the user can actually log in (as opposed to being suspended or inactive).

For security, the `hashedPassword` getter returns a copy of the password hash rather than the original reference. This prevents someone from modifying the internal state accidentally.

### The Role Entity

Roles represent a collection of permissions and can form hierarchies. A role can have a parent role, and through inheritance, it gets all the parent's permissions plus its own.

I built in protection against circular references - a role can't be its own parent, which would create an infinite loop. The role also tracks its own permissions and provides methods to add or remove them.

The `hasPermission()` method checks whether a specific permission ID is part of this role. Because roles can have parents, you might want to implement a recursive check that walks up the hierarchy to see if any parent role has the permission.

### The Permission Entity

Permissions are the finest-grained unit of access control. Each permission specifies a resource (like "invoice" or "document") and an action (like "read", "write", or "delete").

The `matches()` method is the core of the permission system - it takes a resource and action and tells you whether this permission covers that combination. It's simple but effective.

### The Policy Entity

Policies are more complex than permissions. They can contain conditions that determine whether the policy applies in a specific situation. A policy has an effect (allow or deny) and a set of conditions evaluated at runtime.

The `evaluate()` method is where the magic happens - it takes a context object and checks whether all the conditions match. In a real implementation, this would probably use a more sophisticated rule engine, but I've kept it simple for clarity.

## Value Objects

Value objects are different from entities - they don't have identity, and they're defined entirely by their values. Two email objects with the same address are interchangeable.

### Email

The Email value object validates that the address is in a proper format during construction. If someone tries to create an Email with an invalid address, it throws an error immediately.

I normalize all emails to lowercase because email addresses are case-insensitive in practice. The `equals()` method makes it easy to compare two emails, and `toString()` gives you the string representation when you need it.

### PasswordHash

This represents a hashed password. The constructor just takes the hash string - we don't store plain text passwords anywhere.

I included static and instance methods for password handling, but they're marked as requiring the argon2 library. The `fromPlainPassword()` method would create a new hash from a plain text password, and `verifyPassword()` checks whether a plain text password matches the hash.

### TokenId

Token IDs are unique identifiers for tokens. The constructor can take a specific value, or if you don't provide one, it generates a unique ID using a combination of timestamp and random characters.

### AuditLogEntry

Audit logs record what happened, when it happened, and who did it. Each entry has a user ID, action, timestamp, and additional details. The `toJSON()` method converts the entry to a format suitable for storage, with the timestamp converted to ISO format.

## What This All Means

By keeping the domain layer pure and framework-free, we've made the system easy to test. You can create users, roles, and policies, then verify their behavior without spinning up a database or HTTP server.

The encapsulation means bugs are harder to introduce - you can't accidentally set a user's status to an invalid value because the entity doesn't allow it. The business logic lives in one place and can't be scattered around the codebase.

This approach does require more upfront design work, but I've found it pays off in reduced bugs and easier maintenance as the system grows.
