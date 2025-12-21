# Architecture Documentation

## Hexagonal Architecture Implementation

This POC implements hexagonal architecture (also known as ports and adapters architecture) to ensure clean separation of concerns and maintainability.

### Core Principles

1. **Domain-Centric**: Business logic is isolated in the domain layer
2. **Dependency Inversion**: Dependencies point inward toward the domain
3. **Technology Agnostic**: Core business logic doesn't depend on frameworks
4. **Testability**: Each layer can be tested independently

## Backend Architecture (Spring Boot)

### Layer Structure

```
┌─────────────────────────────────────────┐
│        Infrastructure Layer             │
│  (Adapters - Web, Security, Config)     │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │      Application Layer             │ │
│  │  (Use Cases, Ports)                │ │
│  │                                     │ │
│  │  ┌──────────────────────────────┐  │ │
│  │  │    Domain Layer              │  │ │
│  │  │  (Business Logic, Entities)  │  │ │
│  │  └──────────────────────────────┘  │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### Domain Layer
**Location**: `domain/model/`

**Responsibilities**:
- Define core business entities
- Contain business logic
- No dependencies on outer layers

**Example**: `User.java`
- Immutable domain entity using Java 25 records
- Pure data structure with no framework dependencies
- No external libraries like Lombok required

### Application Layer
**Location**: `application/`

**Components**:

1. **Input Ports** (`application/port/in/`):
   - Define use case interfaces
   - Example: `GetUserInfoUseCase`
   - Contract for what the application can do

2. **Output Ports** (`application/port/out/`):
   - Define interfaces for external dependencies
   - Example: `AuthenticationPort`
   - Abstractions for infrastructure services

3. **Services** (`application/service/`):
   - Implement use cases
   - Orchestrate domain objects
   - Call output ports when needed
   - Example: `UserService` implements `GetUserInfoUseCase`

### Infrastructure Layer
**Location**: `infrastructure/`

**Components**:

1. **Input Adapters** (`infrastructure/adapter/in/web/`):
   - REST controllers
   - Handle HTTP requests
   - Convert requests to use case calls
   - Example: `UserController`

2. **Output Adapters** (`infrastructure/adapter/out/security/`):
   - Implementation of output ports
   - Integration with external systems
   - Example: `KeycloakAuthenticationAdapter`

3. **Configuration** (`infrastructure/config/`):
   - Spring configurations
   - Security setup
   - Bean definitions
   - Example: `SecurityConfig`

### Data Flow

```
HTTP Request → Controller (In Adapter)
                    ↓
            Use Case Interface (In Port)
                    ↓
            Application Service
                    ↓
            Output Port Interface
                    ↓
            Output Adapter (Keycloak)
                    ↓
            External System (Keycloak)
```

## Frontend Architecture (React + TypeScript)

### Layer Structure

```
┌─────────────────────────────────────────┐
│           UI Layer                      │
│  (Components, Pages)                    │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │      Use Cases Layer               │ │
│  │  (Custom Hooks - App Logic)        │ │
│  │                                     │ │
│  │  ┌──────────────────────────────┐  │ │
│  │  │    Adapters Layer            │  │ │
│  │  │  (Keycloak, API)             │  │ │
│  │  │                               │  │ │
│  │  │  ┌────────────────────────┐  │  │ │
│  │  │  │  Domain Layer          │  │  │ │
│  │  │  │  (Types, Interfaces)   │  │  │ │
│  │  │  └────────────────────────┘  │  │ │
│  │  └──────────────────────────────┘  │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### Domain Layer
**Location**: `domain/`

**Responsibilities**:
- Define domain types and interfaces
- Pure TypeScript types
- No framework dependencies

**Files**:
- `User.ts`: User entity type
- `AppInfo.ts`: Application information type

### Adapters Layer
**Location**: `adapters/`

**Components**:

1. **KeycloakAdapter**:
   - Implements `IKeycloakPort` interface
   - Handles authentication flow
   - Manages tokens and session
   - Encapsulates Keycloak SDK

2. **ApiAdapter**:
   - Implements `IApiPort` interface
   - Handles backend communication
   - Adds authentication headers
   - Converts responses to domain types

**Benefits**:
- Easy to mock for testing
- Can swap implementations without changing business logic
- Clear contract via interfaces

### Use Cases Layer
**Location**: `useCases/`

**Components**:

1. **useAuth Hook**:
   - Manages authentication state
   - Delegates to KeycloakAdapter
   - Provides auth operations to UI

2. **useAppData Hook**:
   - Fetches application data
   - Delegates to ApiAdapter
   - Manages loading and error states

**Benefits**:
- Reusable business logic
- Testable independently of UI
- Clear separation of concerns

### UI Layer
**Location**: `ui/`

**Structure**:

1. **Components** (`ui/components/`):
   - Reusable UI elements
   - Examples: `Header`, `AppCard`
   - Receive data via props
   - Pure presentation logic

2. **Pages** (`ui/pages/`):
   - Full page layouts
   - Examples: `Dashboard`, `LoginPage`
   - Compose components
   - Connect to use cases via hooks

### Data Flow

```
User Interaction → Component
                      ↓
                  Custom Hook (Use Case)
                      ↓
                    Adapter
                      ↓
                  External System
                   (Keycloak/Backend)
```

## Security Architecture

### Authentication Flow

```
1. User → Frontend
2. Frontend → Keycloak (login)
3. Keycloak → Frontend (JWT token)
4. Frontend → Backend (token in header)
5. Backend → Keycloak (validate token)
6. Backend → Frontend (protected data)
```

### Token Management

**Frontend**:
- Keycloak adapter manages token storage
- Automatic token refresh (every 60 seconds)
- Token included in all API requests

**Backend**:
- OAuth2 Resource Server validates tokens
- Extracts user info from JWT claims
- Stateless authentication

### SSO Implementation

**Key Components**:

1. **Shared Keycloak Realm**:
   - Single realm (`sso-poc`)
   - Multiple clients (app-a, app-b, app-c)
   - Shared user database

2. **Session Sharing**:
   - Keycloak maintains session
   - check-sso mode detects existing sessions
   - Silent SSO checks via iframe

3. **PKCE Flow**:
   - Enhanced security for public clients
   - Code challenge/verifier mechanism
   - Prevents authorization code interception

## Benefits of This Architecture

### Backend Benefits

1. **Testability**:
   - Mock ports for unit testing
   - Test domain logic in isolation
   - Integration tests at adapter level

2. **Maintainability**:
   - Clear separation of concerns
   - Easy to locate code
   - Changes isolated to specific layers

3. **Flexibility**:
   - Swap Keycloak for another provider
   - Change REST to GraphQL
   - Add new use cases easily

### Frontend Benefits

1. **Testability**:
   - Mock adapters for testing
   - Test hooks independently
   - Test UI with mock data

2. **Reusability**:
   - Share adapters across apps
   - Reuse domain types
   - Common hook patterns

3. **Flexibility**:
   - Change UI library
   - Swap authentication provider
   - Add new features easily

## Trade-offs

### Pros
- Clear boundaries and responsibilities
- Easy to test and maintain
- Technology agnostic core
- Supports team scaling

### Cons
- More files and directories
- Higher initial complexity
- Requires discipline to maintain
- Overkill for very simple apps

## When to Use Hexagonal Architecture

**Good For**:
- Applications expected to grow
- Multiple external integrations
- Long-term maintenance
- Team collaboration

**Maybe Not For**:
- Quick prototypes
- Throwaway code
- Very simple CRUD apps
- Solo weekend projects

## Extending the Architecture

### Adding a New Use Case

1. Create interface in `application/port/in/`
2. Create output port if needed in `application/port/out/`
3. Implement use case in `application/service/`
4. Create adapter in `infrastructure/adapter/`
5. Wire in configuration

### Adding a New Adapter

1. Define port interface in `application/port/out/`
2. Implement adapter in `infrastructure/adapter/out/`
3. Register as Spring bean
4. Inject into service

### Adding a New UI Feature

1. Define domain types if needed
2. Create/extend adapter if needed
3. Create custom hook (use case)
4. Build UI components
5. Compose in page component
