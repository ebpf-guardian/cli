use crate::analyzer::ScanSummary;
use rustyline::DefaultEditor;

pub fn run_repl(mut state: Option<ScanSummary>) -> anyhow::Result<()> {
    let mut rl = DefaultEditor::new()?;
    println!("ebguard REPL (help: ':help', quit: ':q')");
    loop {
        let line = match rl.readline("ebguard> ") {
            Ok(l) => l,
            Err(_) => break,
        };
        match line.trim() {
            ":q" | ":quit" => break,
            ":help" => {
                println!("Commands:\n  :summary\n  :cfg\n  :unreachable\n  :metrics\n  analyze <file.o>");
            }
            cmd if cmd.starts_with("analyze ") => {
                let path = &cmd[8..].trim();
                match crate::main_analyze_file(std::path::Path::new(path)) {
                    Ok(s) => { state = Some(s); println!("Analysis loaded."); }
                    Err(e) => eprintln!("Error: {e}"),
                }
            }
            ":summary" => {
                if let Some(s) = &state { println!("{}", crate::output::formatter::format_output(s, &crate::cli::OutputFormat::Table)?); }
                else { println!("No analysis yet."); }
            }
            ":cfg" => {
                if let Some(s) = &state {
                    if let Some(ascii) = &s.cfg_ascii { println!("{ascii}"); } else { println!("No CFG ASCII available."); }
                } else { println!("No analysis yet."); }
            }
            ":unreachable" => {
                if let Some(s) = &state { println!("Unreachable blocks: {:?}", s.cfg_unreachable_blocks); } else { println!("No analysis yet."); }
            }
            ":metrics" => {
                if let Some(s) = &state {
                    println!("Complexity: {}", s.cyclomatic_complexity);
                    println!("Cond branches: {}", s.conditional_branch_count);
                    println!("Path count (exact): {:?}", s.path_count_exact);
                    println!("CFG depth: {}", s.cfg_max_depth);
                    println!("Out-degree avg/max: {}/{}", s.cfg_avg_out_degree, s.cfg_max_out_degree);
                } else { println!("No analysis yet."); }
            }
            "" => {}
            other => println!("Unknown command: {other} (try :help)"),
        }
    }
    Ok(())
}

