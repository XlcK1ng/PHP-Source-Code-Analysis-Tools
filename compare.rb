#!/usr/bin/env ruby

# Author: havoc 
# WWW: https://defuse.ca/backup-verify-script.htm
# Date: Jul 28, 2012
# License: Public domain / Do whatever you want.
#
# Backup validator script. Compares two folders "original" and "backup".
# Alerts the user of any files or directories that are in "original" but not in
# "backup" (extra files in "backup" are ignored). If a file exists in both
# "original" and "backup," they are compared by checking their lengths and by a
# random sample of their contents, and the user is alerted if they differ.
# 
# Output prefixes:
#   DIR:      Directory in original missing from backup.
#   FILE:     File in original missing from, or different, in backup.
#   SKIP:     Skipping directory specified by --ignore.
#   SYMMIS:   Symlink mismatch (one is a symlink, one is a regular file, etc.).
#   SYMLINK:  Symlink to directory skipped and not not following (no --follow).
#   DIFFS     Not recursing into dir because it is on a different filesystem.
#   ERROR:    Error reading file or directory.
#   DEBUG:    Debug information only shown when called with --verbose.

require 'optparse'

# The number of bytes to compare during each random sample comparison.
SampleSize = 32

###############################################################################
#                         Command Line Option Parsing                         #
###############################################################################
$options = {}

optparse = OptionParser.new do |opts|
  opts.banner = "Usage: #{__FILE__} [options] <original> <backup>\n"

  $options[:verbose] = false
  opts.on( '-v', '--verbose', 'Print what is being done' ) do
    $options[:verbose] = true
  end

  $options[:machine] = false
  opts.on( '-m', '--machine', "Output summary in machine-readable format" ) do 
    $options[:machine] = true
  end

  # By default, don't follow symlinks, so we don't end up in infinite loops.
  # The user can override this behaviour if they know there are no loops.
  $options[:follow] = false
  opts.on( '-f', '--[no-]follow', 'Follow symlinks' ) do |val|
    $options[:follow] = val
  end

  # Set this option to NOT cross filesystem boundaries.
  $options[:one_filesystem] = false
  opts.on( '-x', '--one-filesystem', 'Stay on one file system (in <original>)' ) do |val|
    $options[:one_filesystem] = true
  end

  # If a folder in original doesn't exist in backup, the number of items in 
  # the folder will be counted and added to the diff total if invoked with -c
  $options[:count] = false
  opts.on( '-c', '--count', 'Count files in unmatched directories' ) do
    $options[:count] = true
  end

  # Ignored directories can be specified either as a subfolder of original or 
  # backup. The option can be specified multiple times.
  $options[:ignore] = []
  opts.on( '-i', '--ignore DIR', "Don't process DIR" ) do |ignore|
    $options[:ignore] << File.expand_path( ignore )
  end

  $options[:samples] = 0
  opts.on(
    '-s',
    '--samples COUNT',
    "Comparison sample count (default: #{$options[:samples]})"
  ) do |count|
    $options[:samples] = count.to_i
  end

  opts.on( '-h', '--help', 'Display this screen' ) do
    STDOUT.puts opts
    exit
  end
end

begin
  optparse.parse!
rescue OptionParser::InvalidOption
  STDERR.puts "Invalid option"
  STDERR.puts optparse
  exit
end

if ARGV.length < 2
  STDERR.puts "You must specify original and backup folders."
  STDERR.puts optparse
  exit
end

$original = File.expand_path( ARGV[0] )
$backup = File.expand_path( ARGV[1] )

[$original, $backup].each do |dir|
  unless File.directory? dir
    STDERR.puts "[#{dir}] is not a directory."
    STDERR.puts optparse
    exit
  end
end

STDERR.puts "WARNING: Comparing a directory to itself." if $original == $backup

###############################################################################
#                             Directory Comparison                            #
###############################################################################

# Global variables to hold statistics for the summary report at the end.
$diffCount = 0
$itemCount = 0
$skippedCount = 0
$errorCount = 0

# Returns true if fileA and fileB both exist, both are the same size, and pass
# the random sample comparison test.
def sameFile( fileA, fileB )


  # Both exist.
  return false unless File.exists?( fileA ) and File.exists?( fileB )
  # Both are the same size.
  aBytes = File.stat( fileA ).size
  bBytes = File.stat( fileB ).size
  return false unless aBytes == bBytes

  # Random sample comparison.
  same = true
  $options[:samples].times do 
    start = rand( aBytes ) 
    length = [aBytes, start + SampleSize].min - start + 1
    aSample = File.read( fileA, length, start )
    bSample = File.read( fileB, length, start )
    same = same && aSample == bSample
  end
  return same
rescue
  STDOUT.puts "ERROR: Can't read file [#{fileA}]"
  $errorCount += 1
  return true # So we don't get two messages for the same file
end

# Returns the number of items in the directory (and subdirectories of) 'dir'
def countItems( dir )
  if $options[:verbose]
    STDOUT.puts "DEBUG: Counting files in [#{dir}]"
  end

  count = 0
  Dir.foreach( dir ) do |item|
    next if item == "." or item == ".."
    count += 1
    fullPath = File.join( dir, item )
    count += countItems( fullPath ) if File.directory? fullPath
  end
  return count
end

# Recursively compare directories specified by a path relative to $original and
# $backup.
def compareDirs( relative = "" )
  # Combine the base path with the relative path
  original = File.expand_path( File.join( $original, relative ) )
  backup = File.expand_path( File.join( $backup, relative ) )

  if $options[:verbose]
    STDOUT.puts "DEBUG: Comparing [#{original}] to [#{backup}]" 
  end

  # Return if this directory has been excluded
  if $options[:ignore].include?( original ) or $options[:ignore].include?( backup )
    $skippedCount += 1
    STDOUT.puts "SKIP: Skipping comparison of [#{original}] and [#{backup}]"
    return
  end

  # Make sure both directories exist
  unless File.directory?( original ) and File.directory?( backup )
    STDOUT.puts "DIR: [#{original}] not found in [#{backup}]"
    # The directory not existing counts as one difference.
    $diffCount += 1 
    if $options[:count]
      # Then each item in the directory counts as yet another item processed and
      # yet another difference.
      item_count = countItems( original )
      $itemCount += item_count
      $diffCount += item_count
    end
    return
  end

  # If both directories exist, we check their contents
  begin
    Dir.foreach( original ) do |item|
      next if item == "." or item == ".."
      $itemCount += 1
      origPath = File.join( original, item )
      backupPath = File.join( backup, item )

      # This check is independent of whether or not the path is a directory or
      # a file. If either is a symlink, make sure they are both symlinks, and
      # that they link to the same thing.
      if File.symlink?( origPath ) || File.symlink?( backupPath )
        if !(File.symlink?( origPath ) && File.symlink?( backupPath )) ||
              File.readlink( origPath ) != File.readlink( backupPath )

          STDOUT.puts "SYMMIS: Symlink mismatch [#{origPath}] and [#{backupPath}]"

          # Count the missing file or directory.
          $diffCount += 1

          # If the original symlink was a directory, then the backup is missing
          # that directory, PLUS all of that directory's contents.
          if File.directory?( origPath ) && $options[:count]
            item_count = countItems( origPath )
            $itemCount += item_count
            $diffCount += item_count
          end

          # We know these paths are different, so move on to the next one.
          next
        end
      end

      if File.directory? origPath
        # Skip symlinks if told to do so...
        if File.symlink?( origPath ) and not $options[:follow]
          $skippedCount += 1
          STDOUT.puts "SYMLINK: [#{origPath}] skipped."
          next
        end
        # Stay on one filesystem if told to do so...
        outerDev = File::Stat.new( original ).dev
        innerDev = File::Stat.new( origPath ).dev
        if outerDev != innerDev and $options[:one_filesystem]
          $skippedCount += 1
          STDOUT.puts "DIFFFS: [#{origPath}] is on a different file system. Skipped."
          next
        end
        compareDirs( File.join( relative, item ) )
      else # It's a file
        unless sameFile( origPath, backupPath )
          $diffCount += 1
          STDOUT.puts "FILE: [#{origPath}] not found at, or doesn't match [#{backupPath}]"
        end
      end
    end # Dir.foreach
  rescue Errno::EACCES
    STDOUT.puts "ERROR: Can't read directory [#{original}]"
    $errorCount += 1
  end
end # compareDirs

def printSummary
  differPercent = "%.2f" % ($diffCount.to_f / $itemCount.to_f * 100)
  if $options[:machine]
    STDOUT.puts "SUMMARY: items:#{$itemCount}, diff:#{$diffCount}, " +
                "diffpct:#{differPercent}, skip:#{$skippedCount}, " + 
                "err:#{$errorCount}"
  else
    STDOUT.puts "\nSUMMARY:"
    STDOUT.puts "    Items processed: #{$itemCount}"
    STDOUT.puts "    Differences: #{$diffCount} (#{differPercent}%)"
    STDOUT.puts "    Similarities: #{$itemCount - $diffCount}"
    STDOUT.puts "    Skipped: #{$skippedCount}"
    STDOUT.puts "    Errors: #{$errorCount}"
  end
end

# Exit gracefully on CTRL+C
trap( "SIGINT" ) do
  STDOUT.puts "\n\nCaught SIGINT. Stopping."
  printSummary
  exit
end

# Count the "root" directory as an item processed.
$itemCount += 1
compareDirs
printSummary

