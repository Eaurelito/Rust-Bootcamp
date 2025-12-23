use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::fs;
use std::io::Write;
use std::thread;
use std::time::Duration;

use clap::Parser;
use rand::Rng;

#[derive(Copy, Clone, Eq, PartialEq)]
struct State {
    cost: u32,
    pos: (usize, usize),
}

impl Ord for State {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .cost
            .cmp(&self.cost)
            .then_with(|| self.pos.cmp(&other.pos))
    }
}

impl PartialOrd for State {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
struct MaxState {
    cost: u32,
    pos: (usize, usize),
}

impl Ord for MaxState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cost
            .cmp(&other.cost)
            .then_with(|| self.pos.cmp(&other.pos))
    }
}

impl PartialOrd for MaxState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct Map {
    grid: Vec<Vec<u8>>,
    rows: usize,
    cols: usize,
}

impl Map {
    fn from_file(filename: &str) -> Result<Self, String> {
        // Check if file exists
        if !std::path::Path::new(filename).exists() {
            return Err(format!("File not found: {}", filename));
        }

        let content = fs::read_to_string(filename)
            .map_err(|e| format!("Cannot read file '{}': {}", filename, e))?;

        if content.trim().is_empty() {
            return Err("File is empty".to_string());
        }

        let mut grid: Vec<Vec<u8>> = Vec::new();
        let mut line_num = 0;

        for line in content.lines() {
            line_num += 1;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let values: Vec<&str> = line.split_whitespace().collect();
            if values.is_empty() {
                continue;
            }

            let row: Result<Vec<u8>, _> = values
                .iter()
                .enumerate()
                .map(|(col, s)| {
                    u8::from_str_radix(s, 16).map_err(|_| {
                        format!(
                            "Invalid hex value '{}' at line {}, column {}",
                            s,
                            line_num,
                            col + 1
                        )
                    })
                })
                .collect();

            match row {
                Ok(r) => {
                    if !grid.is_empty() && r.len() != grid[0].len() {
                        return Err(format!(
                            "Inconsistent row length at line {}: expected {} values, got {}",
                            line_num,
                            grid[0].len(),
                            r.len()
                        ));
                    }
                    grid.push(r);
                }
                Err(e) => return Err(e),
            }
        }

        if grid.is_empty() {
            return Err("No valid data found in file".to_string());
        }

        let cols = grid[0].len();
        let rows = grid.len();

        if rows < 2 || cols < 2 {
            return Err(format!(
                "Grid too small: {}x{} (minimum 2x2 required)",
                cols, rows
            ));
        }

        if grid[0][0] != 0x00 {
            return Err(format!(
                "Top-left cell must be 00, found {:02X}",
                grid[0][0]
            ));
        }
        if grid[rows - 1][cols - 1] != 0xFF {
            return Err(format!(
                "Bottom-right cell must be FF, found {:02X}",
                grid[rows - 1][cols - 1]
            ));
        }

        Ok(Map { grid, rows, cols })
    }

    fn generate(rows: usize, cols: usize) -> Result<Self, String> {
        if rows < 2 || cols < 2 {
            return Err(format!(
                "Grid dimensions too small: {}x{} (minimum 2x2 required)",
                cols, rows
            ));
        }

        if rows > 1000 || cols > 1000 {
            return Err(format!(
                "Grid dimensions too large: {}x{} (maximum 1000x1000)",
                cols, rows
            ));
        }

        let mut rng = rand::thread_rng();
        let mut grid = vec![vec![0u8; cols]; rows];

        for i in 0..rows {
            for j in 0..cols {
                grid[i][j] = rng.gen_range(0x01..=0xFE);
            }
        }

        grid[0][0] = 0x00;
        grid[rows - 1][cols - 1] = 0xFF;

        Ok(Map { grid, rows, cols })
    }

    fn save(&self, filename: &str) -> Result<(), String> {
        let mut file = fs::File::create(filename)
            .map_err(|e| format!("Cannot create file '{}': {}", filename, e))?;

        for row in &self.grid {
            let line = row
                .iter()
                .map(|v| format!("{:02X}", v))
                .collect::<Vec<_>>()
                .join(" ");
            writeln!(file, "{}", line)
                .map_err(|e| format!("Write error to '{}': {}", filename, e))?;
        }

        Ok(())
    }

    fn neighbors(&self, pos: (usize, usize)) -> Vec<(usize, usize)> {
        let (r, c) = pos;
        let mut result = Vec::new();

        if r > 0 {
            result.push((r - 1, c));
        }
        if r < self.rows - 1 {
            result.push((r + 1, c));
        }
        if c > 0 {
            result.push((r, c - 1));
        }
        if c < self.cols - 1 {
            result.push((r, c + 1));
        }

        result
    }

    fn dijkstra_min(&self, animate: bool) -> Option<(u32, Vec<(usize, usize)>)> {
        let start = (0, 0);
        let end = (self.rows - 1, self.cols - 1);

        let mut heap = BinaryHeap::new();
        let mut dist: HashMap<(usize, usize), u32> = HashMap::new();
        let mut prev: HashMap<(usize, usize), (usize, usize)> = HashMap::new();
        let mut visited: std::collections::HashSet<(usize, usize)> =
            std::collections::HashSet::new();

        dist.insert(start, 0);
        heap.push(State {
            cost: 0,
            pos: start,
        });

        while let Some(State { cost, pos }) = heap.pop() {
            if animate {
                let current_path = self.reconstruct_path(&prev, pos);
                self.visualize_step(pos, cost, &dist, &visited, &current_path, "MINIMUM");
                thread::sleep(Duration::from_millis(150));
            }

            if pos == end {
                return Some((cost, self.reconstruct_path(&prev, end)));
            }

            if cost > *dist.get(&pos).unwrap_or(&u32::MAX) {
                continue;
            }

            visited.insert(pos);

            for next_pos in self.neighbors(pos) {
                let next_cost = cost + self.grid[next_pos.0][next_pos.1] as u32;

                if next_cost < *dist.get(&next_pos).unwrap_or(&u32::MAX) {
                    dist.insert(next_pos, next_cost);
                    prev.insert(next_pos, pos);
                    heap.push(State {
                        cost: next_cost,
                        pos: next_pos,
                    });
                }
            }
        }

        None
    }

    fn dijkstra_max(&self, animate: bool) -> Option<(u32, Vec<(usize, usize)>)> {
        let start = (0, 0);
        let end = (self.rows - 1, self.cols - 1);

        let mut heap = BinaryHeap::new();
        let mut dist: HashMap<(usize, usize), u32> = HashMap::new();
        let mut prev: HashMap<(usize, usize), (usize, usize)> = HashMap::new();
        let mut visited: std::collections::HashSet<(usize, usize)> =
            std::collections::HashSet::new();

        dist.insert(start, 0);
        heap.push(MaxState {
            cost: 0,
            pos: start,
        });

        while let Some(MaxState { cost, pos }) = heap.pop() {
            if visited.contains(&pos) {
                continue;
            }

            visited.insert(pos);

            if animate {
                let current_path = self.reconstruct_path(&prev, pos);
                self.visualize_step(pos, cost, &dist, &visited, &current_path, "MAXIMUM");
                thread::sleep(Duration::from_millis(150));
            }

            if pos == end {
                return Some((cost, self.reconstruct_path(&prev, end)));
            }

            for next_pos in self.neighbors(pos) {
                if visited.contains(&next_pos) {
                    continue;
                }

                let next_cost = cost + self.grid[next_pos.0][next_pos.1] as u32;

                if next_cost > *dist.get(&next_pos).unwrap_or(&0) {
                    dist.insert(next_pos, next_cost);
                    prev.insert(next_pos, pos);
                    heap.push(MaxState {
                        cost: next_cost,
                        pos: next_pos,
                    });
                }
            }
        }

        None
    }

    fn reconstruct_path(
        &self,
        prev: &HashMap<(usize, usize), (usize, usize)>,
        end: (usize, usize),
    ) -> Vec<(usize, usize)> {
        let mut path = vec![end];
        let mut current = end;

        while let Some(&p) = prev.get(&current) {
            path.push(p);
            current = p;
        }

        path.reverse();
        path
    }

    fn hex_to_rgb(value: u8) -> (u8, u8, u8) {
        let hue = (value as f32 / 255.0) * 360.0;
        let (r, g, b) = hsv_to_rgb(hue, 1.0, 1.0);
        ((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
    }

    fn visualize(
        &self,
        path: Option<&Vec<(usize, usize)>>,
        title: &str,
        cost: Option<u32>,
        path_type: &str,
    ) {
        println!("\n{}", title);
        println!("{}", "=".repeat(self.cols * 3));
        println!();

        let path_set: std::collections::HashSet<_> =
            path.map(|p| p.iter().collect()).unwrap_or_default();

        for (i, row) in self.grid.iter().enumerate() {
            for (j, &val) in row.iter().enumerate() {
                let (r, g, b) = Self::hex_to_rgb(val);

                if path_set.contains(&(i, j)) {
                    // Show minimum path in white, maximum path in red
                    if path_type == "maximum" {
                        print!("\x1b[1;91m{:02X}\x1b[0m ", val); // Bright red
                    } else {
                        print!("\x1b[1;97m{:02X}\x1b[0m ", val); // Bright white
                    }
                } else {
                    print!("\x1b[38;2;{};{};{}m{:02X}\x1b[0m ", r, g, b, val);
                }
            }
            println!();
        }

        if let Some(c) = cost {
            println!("\nCost: {} ({})", c, path_type);
        }
    }

    fn print_plain(&self) {
        for row in &self.grid {
            let line = row
                .iter()
                .map(|v| format!("{:02X}", v))
                .collect::<Vec<_>>()
                .join(" ");
            println!("{}", line);
        }
    }

    fn print_path_details(&self, total_cost: u32, path: &Vec<(usize, usize)>) {
        println!("\nTotal cost: 0x{:X} ({} decimal)", total_cost, total_cost);
        println!("Path length: {} steps", path.len() - 1);

        // Print path coordinates
        print!("Path:\n");
        for (i, pos) in path.iter().enumerate() {
            print!("({},{})", pos.0, pos.1);
            if i < path.len() - 1 {
                print!("→");
            }
        }
        println!("\n");

        // Print step-by-step costs
        println!("Step-by-step costs:");
        let mut cumulative = 0u32;
        for (i, pos) in path.iter().enumerate() {
            let cell_value = self.grid[pos.0][pos.1] as u32;
            if i == 0 {
                println!("Start 0x{:02X} ({},{})", cell_value, pos.0, pos.1);
            } else {
                cumulative += cell_value;
                println!(
                    "→ 0x{:02X} ({},{}) +{}",
                    cell_value, pos.0, pos.1, cumulative
                );
            }
        }
        println!("Total: 0x{:X} ({})", total_cost, total_cost);
    }

    fn visualize_step(
        &self,
        current: (usize, usize),
        current_cost: u32,
        dist: &HashMap<(usize, usize), u32>,
        visited: &std::collections::HashSet<(usize, usize)>,
        current_path: &Vec<(usize, usize)>,
        path_type: &str,
    ) {
        print!("\x1b[2J\x1b[H"); // Clear screen

        println!("Pathfinding Animation - {} COST PATH", path_type);
        println!("{}", "=".repeat(50));
        println!(
            "Current position: ({},{}) | Accumulated cost: 0x{:X} ({})",
            current.0, current.1, current_cost, current_cost
        );
        println!("Path length to current: {} steps", current_path.len() - 1);
        println!();

        let path_set: std::collections::HashSet<_> = current_path.iter().collect();

        for (i, row) in self.grid.iter().enumerate() {
            for (j, &val) in row.iter().enumerate() {
                let (r, g, b) = Self::hex_to_rgb(val);

                if (i, j) == current {
                    // Current node - bright yellow/gold background
                    print!("\x1b[1;30;48;5;226m {:02X} \x1b[0m", val);
                } else if path_set.contains(&(i, j)) {
                    // Current best path - bright white
                    print!("\x1b[1;97m {:02X} \x1b[0m", val);
                } else if visited.contains(&(i, j)) {
                    // Already explored - dimmed color
                    print!("\x1b[2;38;2;{};{};{}m {:02X} \x1b[0m", r, g, b, val);
                } else if dist.contains_key(&(i, j)) {
                    // In queue (frontier) - normal brightness
                    print!("\x1b[38;2;{};{};{}m {:02X} \x1b[0m", r, g, b, val);
                } else {
                    // Not yet explored - very dim
                    print!("\x1b[2;90m {:02X} \x1b[0m", val);
                }
            }
            println!();
        }

        println!("\nLegend:");
        println!("\x1b[1;30;48;5;226m XX \x1b[0m Current node being explored");
        println!("\x1b[1;97m XX \x1b[0m Current best path (white)");
        println!("\x1b[2;90m XX \x1b[0m Dimmed: Already explored");
        println!("\x1b[38;2;255;0;0m XX \x1b[0m Colored: Not yet explored or in queue");
    }
}

fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (f32, f32, f32) {
    let c = v * s;
    let h = h / 60.0;
    let x = c * (1.0 - ((h % 2.0) - 1.0).abs());
    let m = v - c;

    let (r, g, b) = match h as i32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };

    (r + m, g + m, b + m)
}

/// Find min/max cost paths in hexadecimal grid
#[derive(Parser)]
#[command(name = "hexpath")]
#[command(about = "Find min/max cost paths in hexadecimal grid.", long_about = None)]
#[command(
    after_help = "Map format:\n  - Each cell: 00-FF (hexadecimal)\n  - Start: top-left (must be 00)\n  - End: bottom-right (must be FF)\n  - Moves: up, down, left, right"
)]
struct Cli {
    /// Map file (hex values, space separated)
    map_file: Option<String>,

    /// Generate random map (e.g., 8x4, 10x10)
    #[arg(long, value_name = "SIZE")]
    generate: Option<String>,

    /// Save generated map to file
    #[arg(long, value_name = "FILE")]
    output: Option<String>,

    /// Show colored map
    #[arg(long)]
    visualize: bool,

    /// Show both min and max paths
    #[arg(long)]
    both: bool,

    /// Animate pathfinding
    #[arg(long)]
    animate: bool,
}

fn main() {
    let cli = Cli::parse();
    let map = if let Some(size) = cli.generate {
        let parts: Vec<&str> = size.split('x').collect();
        if parts.len() != 2 {
            eprintln!("Error: Invalid size format. Use WIDTHxHEIGHT (e.g., 8x4)");
            return;
        }

        let cols = parts[0].parse().unwrap_or(10);
        let rows = parts[1].parse().unwrap_or(10);

        let generated_map = match Map::generate(rows, cols) {
            Ok(m) => m, // ← This extracts the Map from Result
            Err(e) => {
                eprintln!("Error generating map: {}", e);
                std::process::exit(1);
            }
        };

        println!("\nGenerated Map :");
        generated_map.print_plain();
        println!();

        if let Some(file) = cli.output {
            if let Err(e) = generated_map.save(&file) {
                eprintln!("Error: {}", e);
                return;
            }
            println!("Map saved to {}", file);
        }

        generated_map
    } else if let Some(file) = cli.map_file {
        match Map::from_file(&file) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Error: {}", e);
                return;
            }
        }
    } else {
        eprintln!("Error: Provide a map file or use --generate");
        std::process::exit(1);
    };

    if cli.visualize && !cli.animate {
        map.visualize(None, "HEXADECIMAL GRID (rainbow gradient):", None, "");
    }

    // Always calculate and show minimum path
    let min_result = map.dijkstra_min(cli.animate);

    // Calculate maximum path if requested
    let max_result = if cli.both {
        map.dijkstra_max(cli.animate)
    } else {
        None
    };

    // Now display results after all animations are complete
    if cli.animate {
        // Clear screen after animations
        print!("\x1b[2J\x1b[H");
        println!("Pathfinding complete!\n");
    }

    // Display minimum path results
    if !cli.visualize {
        println!("MINIMUM COST PATH:");
        println!("{}", "=".repeat(17));
    }

    if let Some((cost, path)) = min_result {
        if cli.visualize {
            map.visualize(
                Some(&path),
                "MINIMUM COST PATH (shown in WHITE):",
                Some(cost),
                "minimum",
            );
        }
        map.print_path_details(cost, &path);
    } else {
        println!("No minimum path found");
    }

    // Display maximum path results if requested
    if cli.both {
        if !cli.visualize {
            println!("\nMAXIMUM COST PATH:");
            println!("{}", "=".repeat(17));
        }

        if let Some((cost, path)) = max_result {
            if cli.visualize {
                map.visualize(
                    Some(&path),
                    "MAXIMUM COST PATH (shown in RED):",
                    Some(cost),
                    "maximum",
                );
            }
            map.print_path_details(cost, &path);
        } else {
            println!("No maximum path found");
        }
    }
}
