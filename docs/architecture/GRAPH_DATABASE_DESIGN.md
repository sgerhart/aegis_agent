# Graph Database Design - Local Host Intelligence

## 🎯 **Overview**

The local graph database is a revolutionary new capability that provides the Aegis Agent with complete contextual understanding of the host environment. This graph-based approach enables intelligent, relationship-aware security decisions and comprehensive host intelligence.

---

## 🏗️ **Architecture Design**

### **High-Level Architecture**
```
┌─────────────────────────────────────────────────────────────────┐
│                    GRAPH DATABASE MODULE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │   Graph     │  │  Discovery  │  │  Analysis   │  │ Replication│ │
│  │   Engine    │  │   Engine    │  │   Engine    │  │  Engine  │ │
│  │             │  │             │  │             │  │          │ │
│  │ - Neo4j     │  │ - Host      │  │ - Query     │  │ - Sync   │ │
│  │   Embedded  │  │   Discovery │  │   Processing│  │ - Conflict│ │
│  │ - Cypher    │  │ - Process   │  │ - Pattern   │  │   Resolution│ │
│  │   Queries   │  │   Tracking  │  │   Matching  │  │ - Offline │ │
│  │ - Graph     │  │ - Network   │  │ - Algorithms│  │   Support │ │
│  │   Algorithms│  │   Mapping   │  │ - ML        │  │          │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │   Security  │  │   Policy    │  │   Event     │  │  Cache  │ │
│  │   Engine    │  │   Engine    │  │   Engine    │  │ Manager │ │
│  │             │  │             │  │             │  │         │ │
│  │ - Threat    │  │ - Context   │  │ - Correlation│  │ - LRU   │ │
│  │   Detection │  │   Aware     │  │ - Pattern   │  │ - TTL   │ │
│  │ - Anomaly   │  │ - Dynamic   │  │   Detection │  │ - Compression│ │
│  │   Detection │  │   Updates   │  │ - Timeline  │  │ - Persistence│ │
│  │ - Risk      │  │ - Validation│  │   Analysis  │  │         │ │
│  │   Assessment│  │ - Rollback  │  │ - Insights  │  │         │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 **Graph Schema Design**

### **Node Types**

#### **1. Host Nodes**
```cypher
// Host information
CREATE (h:Host {
    id: "host-001",
    hostname: "server-01",
    ip_address: "192.168.1.100",
    os: "Linux",
    architecture: "x86_64",
    kernel_version: "5.4.0",
    cpu_cores: 8,
    memory_gb: 32,
    disk_gb: 500,
    created_at: timestamp(),
    updated_at: timestamp()
})
```

#### **2. Process Nodes**
```cypher
// Process information
CREATE (p:Process {
    id: "proc-001",
    pid: 1234,
    name: "nginx",
    command: "/usr/sbin/nginx",
    user: "www-data",
    group: "www-data",
    working_directory: "/var/www",
    started_at: timestamp(),
    cpu_usage: 0.5,
    memory_usage: 1024000,
    status: "running"
})
```

#### **3. Network Nodes**
```cypher
// Network connection information
CREATE (n:NetworkConnection {
    id: "net-001",
    local_ip: "192.168.1.100",
    local_port: 80,
    remote_ip: "10.0.0.5",
    remote_port: 54321,
    protocol: "TCP",
    state: "ESTABLISHED",
    bytes_sent: 1024000,
    bytes_received: 2048000,
    started_at: timestamp()
})
```

#### **4. File Nodes**
```cypher
// File system information
CREATE (f:File {
    id: "file-001",
    path: "/etc/nginx/nginx.conf",
    name: "nginx.conf",
    size: 2048,
    permissions: "644",
    owner: "root",
    group: "root",
    modified_at: timestamp(),
    accessed_at: timestamp(),
    file_type: "config"
})
```

#### **5. User Nodes**
```cypher
// User information
CREATE (u:User {
    id: "user-001",
    username: "admin",
    uid: 1000,
    gid: 1000,
    home_directory: "/home/admin",
    shell: "/bin/bash",
    last_login: timestamp(),
    login_count: 42
})
```

#### **6. Security Event Nodes**
```cypher
// Security event information
CREATE (e:SecurityEvent {
    id: "event-001",
    event_type: "authentication_failure",
    severity: "medium",
    source_ip: "192.168.1.200",
    target_user: "admin",
    timestamp: timestamp(),
    description: "Failed login attempt",
    risk_score: 0.7
})
```

### **Relationship Types**

#### **1. Process Relationships**
```cypher
// Process parent-child relationship
(p1:Process)-[:PARENT_OF]->(p2:Process)

// Process dependency relationship
(p1:Process)-[:DEPENDS_ON]->(p2:Process)

// Process uses file
(p:Process)-[:USES_FILE]->(f:File)

// Process makes network connection
(p:Process)-[:CONNECTS_TO]->(n:NetworkConnection)
```

#### **2. Host Relationships**
```cypher
// Process runs on host
(p:Process)-[:RUNS_ON]->(h:Host)

// File exists on host
(f:File)-[:EXISTS_ON]->(h:Host)

// User belongs to host
(u:User)-[:BELONGS_TO]->(h:Host)

// Network connection on host
(n:NetworkConnection)-[:ON_HOST]->(h:Host)
```

#### **3. Security Relationships**
```cypher
// Security event involves user
(e:SecurityEvent)-[:INVOLVES_USER]->(u:User)

// Security event involves process
(e:SecurityEvent)-[:INVOLVES_PROCESS]->(p:Process)

// Security event involves file
(e:SecurityEvent)-[:INVOLVES_FILE]->(f:File)

// Security event on host
(e:SecurityEvent)-[:ON_HOST]->(h:Host)
```

#### **4. Temporal Relationships**
```cypher
// Event follows event
(e1:SecurityEvent)-[:FOLLOWS]->(e2:SecurityEvent)

// Process started after event
(e:SecurityEvent)-[:TRIGGERED]->(p:Process)

// File modified after event
(e:SecurityEvent)-[:MODIFIED]->(f:File)
```

---

## 🔍 **Discovery Engine**

### **Host Discovery**
```go
type HostDiscovery struct {
    graphDB    *neo4j.Driver
    discovery  *DiscoveryEngine
    scheduler  *Scheduler
}

func (hd *HostDiscovery) DiscoverHost() error {
    // Discover hardware information
    hardware, err := hd.discovery.DiscoverHardware()
    if err != nil {
        return err
    }
    
    // Discover services
    services, err := hd.discovery.DiscoverServices()
    if err != nil {
        return err
    }
    
    // Discover configuration
    config, err := hd.discovery.DiscoverConfiguration()
    if err != nil {
        return err
    }
    
    // Store in graph database
    return hd.storeHostInfo(hardware, services, config)
}
```

### **Process Discovery**
```go
type ProcessDiscovery struct {
    graphDB    *neo4j.Driver
    monitor    *ProcessMonitor
    scheduler  *Scheduler
}

func (pd *ProcessDiscovery) DiscoverProcesses() error {
    processes, err := pd.monitor.GetProcesses()
    if err != nil {
        return err
    }
    
    for _, process := range processes {
        // Discover process relationships
        relationships, err := pd.discoverProcessRelationships(process)
        if err != nil {
            continue
        }
        
        // Store process and relationships
        err = pd.storeProcess(process, relationships)
        if err != nil {
            continue
        }
    }
    
    return nil
}
```

### **Network Discovery**
```go
type NetworkDiscovery struct {
    graphDB    *neo4j.Driver
    monitor    *NetworkMonitor
    scheduler  *Scheduler
}

func (nd *NetworkDiscovery) DiscoverConnections() error {
    connections, err := nd.monitor.GetConnections()
    if err != nil {
        return err
    }
    
    for _, conn := range connections {
        // Map connection to process
        process, err := nd.mapConnectionToProcess(conn)
        if err != nil {
            continue
        }
        
        // Store connection and relationships
        err = nd.storeConnection(conn, process)
        if err != nil {
            continue
        }
    }
    
    return nil
}
```

---

## 🧠 **Analysis Engine**

### **Query Processing**
```go
type QueryEngine struct {
    graphDB    *neo4j.Driver
    cache      *QueryCache
    optimizer  *QueryOptimizer
}

func (qe *QueryEngine) ExecuteQuery(query string, params map[string]interface{}) (*neo4j.Result, error) {
    // Check cache first
    if cached := qe.cache.Get(query, params); cached != nil {
        return cached, nil
    }
    
    // Optimize query
    optimizedQuery, err := qe.optimizer.Optimize(query, params)
    if err != nil {
        return nil, err
    }
    
    // Execute query
    session := qe.graphDB.NewSession(neo4j.SessionConfig{})
    defer session.Close()
    
    result, err := session.Run(optimizedQuery, params)
    if err != nil {
        return nil, err
    }
    
    // Cache result
    qe.cache.Set(query, params, result)
    
    return result, nil
}
```

### **Pattern Matching**
```go
type PatternMatcher struct {
    graphDB    *neo4j.Driver
    patterns   map[string]*Pattern
    matcher    *PatternMatcher
}

func (pm *PatternMatcher) FindPatterns(patternName string, params map[string]interface{}) ([]*Match, error) {
    pattern, exists := pm.patterns[patternName]
    if !exists {
        return nil, fmt.Errorf("pattern %s not found", patternName)
    }
    
    // Convert pattern to Cypher query
    query := pm.patternToCypher(pattern, params)
    
    // Execute query
    result, err := pm.ExecuteQuery(query, params)
    if err != nil {
        return nil, err
    }
    
    // Convert results to matches
    matches := pm.resultToMatches(result)
    
    return matches, nil
}
```

### **Graph Algorithms**
```go
type GraphAlgorithms struct {
    graphDB    *neo4j.Driver
    algorithms map[string]Algorithm
}

func (ga *GraphAlgorithms) RunAlgorithm(algorithmName string, params map[string]interface{}) (*Result, error) {
    algorithm, exists := ga.algorithms[algorithmName]
    if !exists {
        return nil, fmt.Errorf("algorithm %s not found", algorithmName)
    }
    
    return algorithm.Run(ga.graphDB, params)
}

// Available algorithms
var algorithms = map[string]Algorithm{
    "shortest_path":    &ShortestPathAlgorithm{},
    "pagerank":         &PageRankAlgorithm{},
    "community":        &CommunityDetectionAlgorithm{},
    "centrality":       &CentralityAlgorithm{},
    "clustering":       &ClusteringAlgorithm{},
}
```

---

## 🔒 **Security Engine**

### **Threat Detection**
```go
type ThreatDetector struct {
    graphDB    *neo4j.Driver
    patterns   map[string]*ThreatPattern
    ml         *MachineLearning
}

func (td *ThreatDetector) DetectThreats() ([]*Threat, error) {
    var threats []*Threat
    
    // Pattern-based detection
    for name, pattern := range td.patterns {
        matches, err := td.findPatternMatches(pattern)
        if err != nil {
            continue
        }
        
        for _, match := range matches {
            threat := &Threat{
                Pattern:    name,
                Severity:   pattern.Severity,
                Confidence: match.Confidence,
                Entities:   match.Entities,
                Timestamp:  time.Now(),
            }
            threats = append(threats, threat)
        }
    }
    
    // ML-based detection
    mlThreats, err := td.ml.DetectAnomalies()
    if err != nil {
        return threats, err
    }
    
    threats = append(threats, mlThreats...)
    
    return threats, nil
}
```

### **Anomaly Detection**
```go
type AnomalyDetector struct {
    graphDB    *neo4j.Driver
    baselines  map[string]*Baseline
    ml         *MachineLearning
}

func (ad *AnomalyDetector) DetectAnomalies() ([]*Anomaly, error) {
    var anomalies []*Anomaly
    
    // Behavioral analysis
    behaviors, err := ad.analyzeBehaviors()
    if err != nil {
        return nil, err
    }
    
    for _, behavior := range behaviors {
        baseline, exists := ad.baselines[behavior.Type]
        if !exists {
            continue
        }
        
        if ad.isAnomalous(behavior, baseline) {
            anomaly := &Anomaly{
                Type:        behavior.Type,
                Severity:    ad.calculateSeverity(behavior, baseline),
                Confidence:  ad.calculateConfidence(behavior, baseline),
                Entities:    behavior.Entities,
                Timestamp:   time.Now(),
            }
            anomalies = append(anomalies, anomaly)
        }
    }
    
    return anomalies, nil
}
```

---

## 🔄 **Replication Engine**

### **Synchronization**
```go
type ReplicationEngine struct {
    localDB    *neo4j.Driver
    remoteDB   *neo4j.Driver
    sync       *Synchronizer
    conflict   *ConflictResolver
}

func (re *ReplicationEngine) Synchronize() error {
    // Get local changes
    localChanges, err := re.sync.GetLocalChanges()
    if err != nil {
        return err
    }
    
    // Get remote changes
    remoteChanges, err := re.sync.GetRemoteChanges()
    if err != nil {
        return err
    }
    
    // Resolve conflicts
    resolvedChanges, err := re.conflict.ResolveConflicts(localChanges, remoteChanges)
    if err != nil {
        return err
    }
    
    // Apply changes
    err = re.applyChanges(resolvedChanges)
    if err != nil {
        return err
    }
    
    return nil
}
```

### **Conflict Resolution**
```go
type ConflictResolver struct {
    strategies map[string]ConflictStrategy
}

func (cr *ConflictResolver) ResolveConflicts(local, remote []*Change) ([]*Change, error) {
    var resolved []*Change
    
    // Group changes by entity
    localGroups := cr.groupChanges(local)
    remoteGroups := cr.groupChanges(remote)
    
    // Resolve conflicts for each entity
    for entityID, localChanges := range localGroups {
        remoteChanges := remoteGroups[entityID]
        
        if len(remoteChanges) == 0 {
            // No remote changes, use local
            resolved = append(resolved, localChanges...)
            continue
        }
        
        if len(localChanges) == 0 {
            // No local changes, use remote
            resolved = append(resolved, remoteChanges...)
            continue
        }
        
        // Resolve conflict
        entityResolved, err := cr.resolveEntityConflict(entityID, localChanges, remoteChanges)
        if err != nil {
            return nil, err
        }
        
        resolved = append(resolved, entityResolved...)
    }
    
    return resolved, nil
}
```

---

## 📊 **Performance Optimization**

### **Caching Strategy**
```go
type CacheManager struct {
    lru        *lru.Cache
    ttl        *TTLCache
    compression *CompressionCache
}

func (cm *CacheManager) Get(key string) (interface{}, bool) {
    // Try LRU cache first
    if value, ok := cm.lru.Get(key); ok {
        return value, true
    }
    
    // Try TTL cache
    if value, ok := cm.ttl.Get(key); ok {
        return value, true
    }
    
    return nil, false
}

func (cm *CacheManager) Set(key string, value interface{}) {
    // Compress value if large
    compressed := cm.compression.Compress(value)
    
    // Store in LRU cache
    cm.lru.Add(key, compressed)
    
    // Store in TTL cache with expiration
    cm.ttl.SetWithTTL(key, compressed, time.Hour)
}
```

### **Query Optimization**
```go
type QueryOptimizer struct {
    rules      []OptimizationRule
    statistics *QueryStatistics
}

func (qo *QueryOptimizer) Optimize(query string, params map[string]interface{}) (string, error) {
    // Parse query
    parsed, err := qo.parseQuery(query)
    if err != nil {
        return "", err
    }
    
    // Apply optimization rules
    optimized := parsed
    for _, rule := range qo.rules {
        optimized = rule.Apply(optimized, qo.statistics)
    }
    
    // Generate optimized query
    return qo.generateQuery(optimized), nil
}
```

---

## 🔧 **Implementation Plan**

### **Phase 1: Core Infrastructure (2-3 weeks)**
1. **Graph Database Setup**
   - Integrate Neo4j embedded
   - Implement basic CRUD operations
   - Create initial schema

2. **Discovery Engine**
   - Implement host discovery
   - Implement process discovery
   - Implement network discovery

3. **Basic Query Engine**
   - Implement Cypher query support
   - Implement basic caching
   - Implement query optimization

### **Phase 2: Analysis Capabilities (2-3 weeks)**
1. **Pattern Matching**
   - Implement pattern definitions
   - Implement pattern matching engine
   - Implement pattern result processing

2. **Graph Algorithms**
   - Implement shortest path algorithm
   - Implement centrality algorithms
   - Implement community detection

3. **Security Analysis**
   - Implement threat detection patterns
   - Implement anomaly detection
   - Implement risk assessment

### **Phase 3: Replication System (2-3 weeks)**
1. **Synchronization**
   - Implement change tracking
   - Implement incremental sync
   - Implement conflict resolution

2. **Offline Support**
   - Implement offline mode
   - Implement change queuing
   - Implement sync on reconnect

3. **Performance Optimization**
   - Implement advanced caching
   - Implement query optimization
   - Implement compression

### **Phase 4: Integration & Testing (1-2 weeks)**
1. **Module Integration**
   - Integrate with existing modules
   - Implement module APIs
   - Implement event handling

2. **Testing & Validation**
   - Implement unit tests
   - Implement integration tests
   - Implement performance tests

---

## 📋 **Success Criteria**

### **Functional Requirements**
- [ ] Complete host discovery and mapping
- [ ] Real-time graph updates
- [ ] Advanced query capabilities
- [ ] Threat detection and analysis
- [ ] Graph replication and sync
- [ ] Offline capability

### **Performance Requirements**
- [ ] Query response time < 100ms
- [ ] Graph update latency < 1s
- [ ] Memory usage < 50MB
- [ ] CPU usage < 20%
- [ ] Storage efficiency > 80%

### **Reliability Requirements**
- [ ] 99.9% uptime
- [ ] Data consistency
- [ ] Conflict resolution
- [ ] Error recovery
- [ ] Backup and restore

---

## 🎯 **Conclusion**

The graph database design provides a comprehensive foundation for host intelligence and context-aware security. With its advanced discovery, analysis, and replication capabilities, it enables the Aegis Agent to provide unprecedented host understanding and intelligent security decisions.

The modular design ensures scalability and maintainability, while the performance optimizations ensure efficient operation in production environments.

---

**Document Version**: 1.0  
**Last Updated**: September 27, 2025  
**Status**: Design Complete, Implementation In Progress
