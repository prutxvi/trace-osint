# Skill: Terminal UI

## Purpose
Deliver a premium, cyber-terminal aesthetic for the investigation console.

## Visual Design
- **Background**: Dark (#0a0a0a)
- **Primary accent**: Phosphor green (#00ff41)
- **Secondary accent**: Cyan (#00d4ff)
- **Warning**: Amber (#ffb000)
- **Error**: Red (#ff0040)
- **Font**: Monospace everywhere

## UI Components
- **Header Panel**: Case ID, phase, policy mode, active agent
- **Tool Activity Panel**: Live tool invocations with status icons
- **Progress Indicators**: Spinners and progress bars for operations
- **Entity Table**: Resolved entities with confidence levels
- **Finding Summary**: Counts and distribution
- **Final Report Panel**: Investigation complete summary

## Status Icons
- `[green]+[/green]` Success/OK
- `[cyan]>[/cyan]` Running
- `[dim]-[/dim]` Pending
- `[red]![/red]` Error
- `[red]X[/red]` Blocked

## Refresh Strategy
- Update UI on phase transitions
- Update tool activity on each tool completion
- Avoid continuous refresh loops
- Use Rich Live for dynamic updates only during active phases
