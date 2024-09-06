import re
import random

def extract_atomic_test_commands(technique_ids, operating_system):
    commands = []

    if operating_system == 'Linux':
        os_pattern = r'```(?:bash|sh)(.*?)```'
    elif operating_system == 'Windows':
        os_pattern = r'```(?:cmd|powershell)(.*?)```'
    
    for technique_id in technique_ids:
        file_path = f'./atomic-red-team/atomics/{technique_id}/{technique_id}.md'
        
        commands_for_technique = []
        inputs_for_technique = []
        
        try:
            with open(file_path, 'r', errors='replace') as file:
                content = file.read()

            atomic_tests = re.split(r'## Atomic Test #\d+', content)

            for idx, test in enumerate(atomic_tests):
                supported_platforms_match = re.search(r'\*\*Supported Platforms:\*\* (.*?)\n', test)
                if supported_platforms_match:
                    supported_platforms = supported_platforms_match.group(1).split(", ")
                    if operating_system in supported_platforms:
                        code_block_match = re.search(os_pattern, test, re.DOTALL)
                        if code_block_match:
                            command = code_block_match.group(1).strip()
                            if command:
                                commands_for_technique.append(command)
                        
                        inputs_table_match = re.search(r'#### Inputs:(.*?)\n\n', test, re.DOTALL)
                        if inputs_table_match:
                            inputs_table = inputs_table_match.group(1).strip()
                            inputs_for_technique.append(inputs_table)

            if commands_for_technique:
                selected_command = random.choice(commands_for_technique)  # Select a random command
                
                if inputs_for_technique:
                    selected_inputs_table = random.choice(inputs_for_technique)  # Select a random inputs table
                    name_to_default_value = extract_name_and_default_value(selected_inputs_table)
                    command_with_defaults = replace_placeholders(selected_command, name_to_default_value)
                else:
                    command_with_defaults = selected_command  # No inputs table found, use the command as-is
                
                commands.append(command_with_defaults)

        except FileNotFoundError:
            print(f"File not found for technique ID: {technique_id}")

    return commands

def extract_name_and_default_value(inputs_table):
    lines = inputs_table.split('\n')
    headers = lines[0].strip().split('|')
    
    name_index = headers.index(' Name ')
    default_value_index = headers.index(' Default Value ')

    name_to_default_value = {}

    for line in lines[2:]:
        columns = line.strip().split('|')
        if len(columns) > max(name_index, default_value_index):
            name = columns[name_index].strip()
            default_value = columns[default_value_index].strip()
            if name and default_value:
                name_to_default_value[name] = default_value

    return name_to_default_value

def replace_placeholders(command, name_to_default_value):
    pattern = r'\{(.*?)\}'
    matches = re.findall(pattern, command)

    for match in matches:
        if match in name_to_default_value:
            command = command.replace(f'{{{match}}}', name_to_default_value[match])
    
    return command