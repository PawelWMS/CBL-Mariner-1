#!/bin/bash

set -e

# Parameters:
# -c - CVE number to search for,
# -k - Kernel spec directory to search for the CVE patches in,
# -r - Linux kernel repository to generate the patch from.
while getopts c:k:r: option
do
    case "${option}" in
        c) CVE_NUMBER=${OPTARG};;
        k) KERNEL_DIRECTORY=${OPTARG};;
        r) REPOSITORY=${OPTARG};;

        *) echo "ERROR: Unsupported flag $1" >&2
           exit 1
           ;;        
    esac
done

if [[ -z "$CVE_NUMBER" ]]
then
    echo "ERROR: No CVE number specified. Please use the -c flag." >&2
    exit 1
fi

if [[ ! "$CVE_NUMBER" =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]]
then
    echo "ERROR: Invalid CVE number format. Please use the format 'CVE-XXXX-YYYY'." >&2
    exit 1
fi

if [[ ! -d "$KERNEL_DIRECTORY" ]]
then
    echo "ERROR: Kernel spec directory ($KERNEL_DIRECTORY) does not exist. Please use -k to point to the kernel's spec directory." >&2
    exit 1
fi

if [[ ! -d "$REPOSITORY" ]]
then
    echo "ERROR: Repository directory ($REPOSITORY) does not exist." >&2
    exit 1
fi

KERNEL_DIRECTORY=$(realpath "$KERNEL_DIRECTORY")
REPOSITORY=$(realpath "$REPOSITORY")

PATCH_HASH="$(find "$KERNEL_DIRECTORY" -name "$CVE_NUMBER*patch" -exec grep -oP "(?<=stable ).*" {} \;)"
if [[ -z "$PATCH_HASH" ]]
then
    echo "Could not find CVE $CVE_NUMBER in kernel spec directory $KERNEL_DIRECTORY. Exiting."
    exit 0
fi

git -C "$REPOSITORY" fetch --all
mv "$(git -C "$REPOSITORY" format-patch "$PATCH_HASH"~1.."$PATCH_HASH" -o "$PWD")" "$PWD/$CVE_NUMBER.patch"
