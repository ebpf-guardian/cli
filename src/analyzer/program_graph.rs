use crate::analyzer::InstructionInfo;
use crate::analyzer::Result;
use petgraph::dot::Dot;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;

/// Represents a basic block in the control flow graph
#[derive(Debug)]
pub struct BasicBlock {
    /// Start offset of the block
    pub start_offset: usize,
    /// Instructions in this block
    pub instructions: Vec<InstructionInfo>,
    /// Edges to other blocks
    pub edges: Vec<usize>,
}

/// Control flow graph for an eBPF program
#[derive(Debug)]
pub struct ControlFlowGraph {
    /// Graph representation
    pub graph: DiGraph<BasicBlock, ()>,
    /// Map from instruction offset to node index
    pub offset_to_node: std::collections::HashMap<usize, NodeIndex>,
    /// Entry node of the program (usually block starting at offset 0)
    pub entry: Option<NodeIndex>,
}

#[derive(Debug)]
pub struct ProgramAnalysis {
    /// Maximum stack depth detected
    pub max_stack_depth: usize,
    /// Number of paths through the program
    pub path_count: usize,
    /// Estimated cyclomatic complexity (McCabe)
    pub cyclomatic_complexity: usize,
    /// Count of conditional branches
    pub conditional_branch_count: usize,
    /// Potential loops detected
    pub loops: Vec<Loop>,
    /// Helper function calls
    pub helper_calls: Vec<HelperCall>,
    /// Map access patterns
    pub map_accesses: Vec<MapAccess>,
    /// Unreachable basic blocks (by start offset)
    pub unreachable_blocks: Vec<usize>,
    /// Maximum CFG depth from entry to any exit (in basic blocks)
    pub max_depth: usize,
    /// Average out-degree across CFG nodes
    pub avg_out_degree: f32,
    /// Maximum out-degree across CFG nodes
    pub max_out_degree: usize,
    /// Entry block offset
    pub entry_offset: usize,
    /// Exit block offsets
    pub exit_offsets: Vec<usize>,
    /// Exact simple path count from entry to exits (capped)
    pub path_count_exact: Option<usize>,
    /// DOT rendering of CFG
    pub cfg_dot: Option<String>,
    /// ASCII rendering of CFG
    pub cfg_ascii: Option<String>,
}

#[derive(Debug)]
pub struct Loop {
    /// Start offset of the loop
    pub start_offset: usize,
    /// End offset of the loop
    pub end_offset: usize,
    /// Whether the loop has a static bound
    pub has_static_bound: bool,
    /// Maximum iterations (if statically determinable)
    pub max_iterations: Option<u32>,
}

#[derive(Debug)]
pub struct HelperCall {
    /// Helper function ID
    pub helper_id: u32,
    /// Instruction offset
    pub offset: usize,
    /// Arguments passed (if statically analyzable)
    pub args: Vec<ArgInfo>,
}

#[derive(Debug)]
pub struct ArgInfo {
    /// Argument register
    pub reg: u8,
    /// Known value if constant
    pub const_value: Option<i64>,
    /// Type of value
    pub value_type: ArgType,
}

#[derive(Debug)]
pub enum ArgType {
    MapFd,
    StackPtr,
    PacketPtr,
    Scalar,
    Unknown,
}

#[derive(Debug)]
pub struct MapAccess {
    /// Map identifier
    pub map_id: String,
    /// Access type (read/write)
    pub access_type: AccessType,
    /// Whether the access is inside a loop
    pub in_loop: bool,
    /// Whether proper bounds checking is done
    pub has_bounds_check: bool,
}

#[derive(Debug)]
pub enum AccessType {
    Read,
    Write,
    Update,
}

impl ControlFlowGraph {
    /// Creates a new control flow graph from instructions
    pub fn new(instructions: &[InstructionInfo]) -> Result<Self> {
        let mut graph = DiGraph::new();
        let mut offset_to_node = std::collections::HashMap::new();
        let mut current_block = Vec::new();
        let mut current_start = 0;

        // First pass: Create basic blocks (end block after including a jump/exit)
        for (i, inst) in instructions.iter().enumerate() {
            current_block.push(inst.clone());
            if is_jump_instruction(inst) {
                let block = BasicBlock {
                    start_offset: current_start,
                    instructions: current_block.clone(),
                    edges: Vec::new(),
                };
                let node_idx = graph.add_node(block);
                offset_to_node.insert(current_start, node_idx);

                current_block = Vec::new();
                current_start = i + 1;
            }
        }

        // Add the last block if not empty
        if !current_block.is_empty() {
            let block = BasicBlock {
                start_offset: current_start,
                instructions: current_block,
                edges: Vec::new(),
            };
            let node_idx = graph.add_node(block);
            offset_to_node.insert(current_start, node_idx);
        }

        // Second pass: Build full offset -> node mapping for all instruction offsets
        for node_idx in graph.node_indices() {
            let start = graph[node_idx].start_offset;
            let len = graph[node_idx].instructions.len();
            for local in 0..len {
                offset_to_node.insert(start + local, node_idx);
            }
        }

        // Third pass: Add edges
        for node_idx in graph.node_indices() {
            let start_offset;
            let instructions_len;
            let last_inst;
            {
                let block = &graph[node_idx];
                start_offset = block.start_offset;
                instructions_len = block.instructions.len();
                last_inst = block.instructions.last().cloned();
            }

            if let Some(last_inst) = last_inst {
                if is_jump_instruction(&last_inst) {
                    // Add edge to jump target
                    let target_offset = (start_offset + instructions_len) as i32 + last_inst.imm;
                    if target_offset >= 0 {
                        if let Some(&target_node) = offset_to_node.get(&(target_offset as usize)) {
                            graph.add_edge(node_idx, target_node, ());
                        }
                    }

                    // Add fallthrough edge for conditional jumps
                    if is_conditional_jump(&last_inst) {
                        let next_offset = start_offset + instructions_len;
                        if let Some(&next_node) = offset_to_node.get(&next_offset) {
                            graph.add_edge(node_idx, next_node, ());
                        }
                    }
                }
            }
        }

        let entry = offset_to_node.get(&0).cloned();

        Ok(Self {
            graph,
            offset_to_node,
            entry,
        })
    }

    /// Gets successors of a node
    pub fn successors(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.graph
            .edges_directed(node, petgraph::Direction::Outgoing)
            .map(|e| e.target())
            .collect()
    }

    /// Gets predecessors of a node
    pub fn predecessors(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.graph
            .edges_directed(node, petgraph::Direction::Incoming)
            .map(|e| e.source())
            .collect()
    }

    /// Renders the CFG in DOT format
    pub fn to_dot(&self) -> String {
        let labeled = self.graph.map(
            |_, bb| format!("BB@{}\\n{} insts", bb.start_offset, bb.instructions.len()),
            |_, _| String::new(),
        );
        format!("{}", Dot::new(&labeled))
    }

    /// Produces a simple ASCII representation of the CFG as adjacency lists
    pub fn to_ascii(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        let mut nodes: Vec<NodeIndex> = self.graph.node_indices().collect();
        nodes.sort_by_key(|n| self.graph[*n].start_offset);
        for n in nodes {
            let bb = &self.graph[n];
            let mut succs: Vec<usize> = self
                .successors(n)
                .iter()
                .map(|s| self.graph[*s].start_offset)
                .collect();
            succs.sort_unstable();
            lines.push(format!(
                "BB@{:>4} -> [{}]",
                bb.start_offset,
                succs
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        lines.join("\n")
    }
}

/// Checks if an instruction is a jump
fn is_jump_instruction(inst: &InstructionInfo) -> bool {
    let class_bits = inst.opcode & 0x07;
    // JMP (0x05) and JMP32 (0x06) classes
    class_bits == 0x05 || class_bits == 0x06
}

/// Checks if an instruction is a conditional jump
fn is_conditional_jump(inst: &InstructionInfo) -> bool {
    let class_bits = inst.opcode & 0x07;
    // Treat JMP/JMP32 with opcode not equal to JA (unconditional jump) as conditional
    // BPF_JA is opcode 0x05 with OP code 0x00, but we don't decode OP here; heuristically:
    class_bits == 0x05 || class_bits == 0x06
}

/// Builds a control flow graph from instructions
pub fn build_graph(instructions: &[InstructionInfo]) -> Result<ControlFlowGraph> {
    ControlFlowGraph::new(instructions)
}

/// Analyzes program for safety and performance issues
pub fn analyze_program(
    cfg: &ControlFlowGraph,
    instructions: &[InstructionInfo],
) -> Result<ProgramAnalysis> {
    let mut analysis = ProgramAnalysis {
        max_stack_depth: 0,
        path_count: 0,
        cyclomatic_complexity: 0,
        conditional_branch_count: 0,
        loops: Vec::new(),
        helper_calls: Vec::new(),
        map_accesses: Vec::new(),
        unreachable_blocks: Vec::new(),
        max_depth: 0,
        avg_out_degree: 0.0,
        max_out_degree: 0,
        entry_offset: cfg.entry.map(|n| cfg.graph[n].start_offset).unwrap_or(0),
        exit_offsets: Vec::new(),
        path_count_exact: None,
        cfg_dot: None,
        cfg_ascii: None,
    };

    // Find loops using Tarjan's algorithm
    let sccs = petgraph::algo::tarjan_scc(&cfg.graph);
    for scc in sccs {
        if scc.len() > 1 {
            // Found a potential loop
            let start = cfg.graph[scc[0]].start_offset;
            let end = cfg.graph[scc[scc.len() - 1]].start_offset;

            // Try to determine loop bound
            let bound_info = analyze_loop_bound(&cfg.graph, &scc, instructions);
            analysis.loops.push(Loop {
                start_offset: start,
                end_offset: end,
                has_static_bound: bound_info.is_some(),
                max_iterations: bound_info,
            });
        }
    }

    // Analyze helper function calls
    for (offset, inst) in instructions.iter().enumerate() {
        if inst.opcode == 0x85 {
            // BPF_CALL
            let helper_id = inst.imm as u32;
            let mut args = Vec::new();

            // Look back to find argument setup
            let mut i = offset as i32 - 1;
            while i >= 0 && args.len() < 5 {
                let prev = &instructions[i as usize];
                if prev.dst_reg <= 5 {
                    // r1-r5 are args
                    args.push(ArgInfo {
                        reg: prev.dst_reg,
                        const_value: if prev.opcode == 0xb7 {
                            // mov imm
                            Some(prev.imm as i64)
                        } else {
                            None
                        },
                        value_type: classify_arg_type(prev),
                    });
                }
                i -= 1;
            }

            analysis.helper_calls.push(HelperCall {
                helper_id,
                offset,
                args,
            });
        }
    }

    // Compute cyclomatic complexity and estimate paths
    let nodes = cfg.graph.node_count();
    let edges = cfg.graph.edge_count();
    // For a single connected component graph P=1
    let cyclo = edges.saturating_sub(nodes).saturating_add(2);
    analysis.cyclomatic_complexity = cyclo;

    // Count conditional branches (rough path upper bound 2^cond)
    let cond_count = instructions
        .iter()
        .filter(|inst| is_conditional_jump(inst))
        .count();
    analysis.conditional_branch_count = cond_count;
    // Estimate path count conservatively with cap
    let estimate = if cond_count >= 20 {
        // cap to avoid pow overflow
        usize::MAX / 2
    } else {
        1usize << cond_count
    };
    analysis.path_count = estimate.min(1_000_000usize);

    // Compute exact simple path count (capped) and max depth
    let (exact_paths, max_depth) = compute_paths_and_depth(cfg);
    analysis.path_count_exact = exact_paths;
    analysis.max_depth = max_depth;

    // Degree metrics
    let mut sum_deg = 0usize;
    let mut max_deg = 0usize;
    for n in cfg.graph.node_indices() {
        let deg = cfg.successors(n).len();
        sum_deg += deg;
        if deg > max_deg {
            max_deg = deg;
        }
    }
    analysis.avg_out_degree = if nodes > 0 {
        sum_deg as f32 / nodes as f32
    } else {
        0.0
    };
    analysis.max_out_degree = max_deg;

    // Track stack depth
    analysis.max_stack_depth = analyze_stack_depth(instructions);

    // Analyze map accesses
    analysis.map_accesses = analyze_map_accesses(cfg, instructions);

    // Determine exit blocks and unreachable blocks
    analysis.exit_offsets = find_exit_blocks(cfg);
    analysis.unreachable_blocks = find_unreachable_blocks(cfg);

    // Embed DOT and ASCII renderings
    analysis.cfg_dot = Some(cfg.to_dot());
    analysis.cfg_ascii = Some(cfg.to_ascii());

    Ok(analysis)
}

/// Analyzes if a loop has a static bound
fn analyze_loop_bound(
    graph: &DiGraph<BasicBlock, ()>,
    scc: &[NodeIndex],
    _instructions: &[InstructionInfo],
) -> Option<u32> {
    // Heuristic: detect simple counting loops comparing against an immediate,
    // with +/-1 steps to the compared register inside the SCC.
    use std::collections::HashSet;
    let scc_set: HashSet<NodeIndex> = scc.iter().copied().collect();

    for node in scc {
        let block = &graph[*node];
        for inst in &block.instructions {
            if is_conditional_jump(inst) {
                let candidate_bound = if inst.imm > 0 {
                    Some(inst.imm as u32)
                } else {
                    None
                };
                if candidate_bound.is_some() {
                    let mut has_step = false;
                    for scc_node in &scc_set {
                        let bb = &graph[*scc_node];
                        for i in &bb.instructions {
                            // ALU64 ADD/SUB immediate to same register pattern (very heuristic)
                            let is_add = i.opcode == 0x07; // add imm
                            let is_sub = i.opcode == 0x0f; // sub imm
                            if (is_add || is_sub) && i.dst_reg == inst.dst_reg && i.imm.abs() == 1 {
                                has_step = true;
                                break;
                            }
                        }
                        if has_step {
                            break;
                        }
                    }
                    if has_step {
                        return candidate_bound;
                    }
                }
            }
        }
    }
    None
}

/// Counts unique paths through the program
#[allow(dead_code)]
fn count_paths(graph: &DiGraph<BasicBlock, ()>, limit: usize) -> usize {
    use petgraph::visit::DfsPostOrder;
    let mut count = 0;
    let mut dfs = DfsPostOrder::new(&graph, graph.node_indices().next().unwrap());
    while dfs.next(&graph).is_some() && count < limit {
        count += 1;
    }
    count
}

/// Analyzes maximum stack depth
fn analyze_stack_depth(instructions: &[InstructionInfo]) -> usize {
    let mut max_depth = 0;
    let mut current_depth = 0;

    for inst in instructions {
        match inst.opcode {
            0x7f => {
                // STX
                if inst.dst_reg == 10 {
                    // r10 is stack pointer
                    current_depth = current_depth.max((-inst.imm) as usize);
                    max_depth = max_depth.max(current_depth);
                }
            }
            _ => {}
        }
    }

    max_depth
}

/// Analyzes map access patterns
fn analyze_map_accesses(
    cfg: &ControlFlowGraph,
    instructions: &[InstructionInfo],
) -> Vec<MapAccess> {
    let mut accesses = Vec::new();
    for node in cfg.graph.node_indices() {
        let block = &cfg.graph[node];

        // Check if this block is part of a loop
        let in_loop = cfg
            .predecessors(node)
            .iter()
            .any(|&pred| cfg.successors(pred).contains(&node));

        for inst in &block.instructions {
            if inst.opcode == 0x85 {
                // BPF_CALL
                match inst.imm {
                    1 => {
                        // bpf_map_lookup_elem
                        accesses.push(MapAccess {
                            map_id: format!("map_{}", inst.src_reg),
                            access_type: AccessType::Read,
                            in_loop,
                            has_bounds_check: has_null_check_after(inst, instructions),
                        });
                    }
                    2 => {
                        // bpf_map_update_elem
                        accesses.push(MapAccess {
                            map_id: format!("map_{}", inst.src_reg),
                            access_type: AccessType::Write,
                            in_loop,
                            has_bounds_check: true, // Update always checks bounds
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    accesses
}

/// Checks if there's a null check after map lookup
fn has_null_check_after(inst: &InstructionInfo, instructions: &[InstructionInfo]) -> bool {
    if let Some(next) = instructions.get(inst.offset + 1) {
        next.opcode == 0x15 && next.imm == 0 // JEQ #0
    } else {
        false
    }
}

/// Classifies argument type based on instruction context
fn classify_arg_type(inst: &InstructionInfo) -> ArgType {
    match inst.opcode {
        0x18 => ArgType::MapFd,     // LDDW for map fd
        0x61 => ArgType::StackPtr,  // STX to stack
        0x71 => ArgType::PacketPtr, // LDX from packet
        0xb7 => ArgType::Scalar,    // MOV imm
        _ => ArgType::Unknown,
    }
}

/// Finds exit blocks (those whose last instruction is EXIT)
fn find_exit_blocks(cfg: &ControlFlowGraph) -> Vec<usize> {
    let mut exits = Vec::new();
    for n in cfg.graph.node_indices() {
        if let Some(last) = cfg.graph[n].instructions.last() {
            if last.opcode == 0x95 || last.disassembly.to_lowercase() == "exit" {
                exits.push(cfg.graph[n].start_offset);
            }
        }
    }
    exits.sort_unstable();
    exits
}

/// Finds unreachable blocks from entry using DFS
fn find_unreachable_blocks(cfg: &ControlFlowGraph) -> Vec<usize> {
    use petgraph::visit::Dfs;
    if cfg.entry.is_none() {
        return Vec::new();
    }
    let entry = cfg.entry.unwrap();
    let mut visited = std::collections::HashSet::new();
    let mut dfs = Dfs::new(&cfg.graph, entry);
    while let Some(nx) = dfs.next(&cfg.graph) {
        visited.insert(nx);
    }
    let mut unreachable = Vec::new();
    for n in cfg.graph.node_indices() {
        if !visited.contains(&n) {
            unreachable.push(cfg.graph[n].start_offset);
        }
    }
    unreachable.sort_unstable();
    unreachable
}

/// Computes the number of simple paths (capped) and maximum depth from entry to any exit
fn compute_paths_and_depth(cfg: &ControlFlowGraph) -> (Option<usize>, usize) {
    let entry = match cfg.entry {
        Some(e) => e,
        None => return (None, 0),
    };
    let exits: Vec<NodeIndex> = cfg
        .graph
        .node_indices()
        .filter(|n| {
            cfg.graph[*n]
                .instructions
                .last()
                .map(|i| i.opcode == 0x95 || i.disassembly.to_lowercase() == "exit")
                .unwrap_or(false)
        })
        .collect();
    if exits.is_empty() {
        return (None, 0);
    }

    let cap: usize = 100_000; // avoid explosion
    let mut path_count: usize = 0;
    let mut max_depth: usize = 0;
    let mut visited: std::collections::HashSet<NodeIndex> = std::collections::HashSet::new();

    fn dfs(
        cfg: &ControlFlowGraph,
        current: NodeIndex,
        exits: &std::collections::HashSet<NodeIndex>,
        visited: &mut std::collections::HashSet<NodeIndex>,
        depth: usize,
        path_count: &mut usize,
        max_depth: &mut usize,
        cap: usize,
    ) {
        if *path_count >= cap {
            return;
        }
        if exits.contains(&current) {
            *path_count += 1;
            if depth > *max_depth {
                *max_depth = depth;
            }
            return;
        }
        visited.insert(current);
        for succ in cfg.successors(current) {
            if visited.contains(&succ) {
                continue;
            }
            dfs(
                cfg,
                succ,
                exits,
                visited,
                depth + 1,
                path_count,
                max_depth,
                cap,
            );
            if *path_count >= cap {
                break;
            }
        }
        visited.remove(&current);
    }

    let exit_set: std::collections::HashSet<NodeIndex> = exits.into_iter().collect();
    dfs(
        cfg,
        entry,
        &exit_set,
        &mut visited,
        0,
        &mut path_count,
        &mut max_depth,
        cap,
    );
    (Some(path_count.min(cap)), max_depth)
}
