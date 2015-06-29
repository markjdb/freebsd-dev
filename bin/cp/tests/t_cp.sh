# $FreeBSD$

atf_test_case cp_file_self_symlink
cp_file_self_symlink_head()
{
	atf_set "descr" "Verify that cp -f follows a target symlink."
}

cp_file_self_symlink_body()
{
	mkfile file1 1
	mksymlink file1 symlink1

	atf_check -s exit:1 -o empty \
	    -e inline:"cp: symlink1 and file1 are identical (not copied).\n" \
	    cp file1 symlink1
}

atf_test_case cp_f_file_to_file_symlink
cp_f_file_to_file_symlink_head()
{
	atf_set "descr" "Verify that cp -f follows a target symlink."
}

cp_f_file_to_file_symlink_body()
{
	mkfile file1 1
	mkfile file2 2
	mksymlink file2 symlink1

	atf_check -s exit:0 -o empty -e empty cp -f file1 symlink1
	atf_check -s exit:0 -o file:file1 -e empty cat symlink1
	atf_check -s exit:0 -o file:file1 -e empty cat file2
}

atf_test_case cp_f_file_to_dangling_symlink
cp_f_file_to_dangling_symlink_head()
{
	atf_set "descr" \
            "Verify that cp -f will create files through a dangling symlink."
}

cp_f_file_to_dangling_symlink_body()
{
	mkfile file1 1
	mksymlink file2 symlink1

	atf_check -s exit:0 -o empty -e empty cp -f file1 symlink1
	atf_check -s exit:0 -o file:file1 -e empty cat symlink1
	atf_check -s exit:0 -o file:file1 -e empty cat file2
}

atf_test_case cp_f_file_to_unopenable_symlink
cp_f_file_to_unopenable_symlink_head()
{
	atf_set "descr" \
            "Verify that cp -f unlinks the target file if it cannot be opened."
}

cp_f_file_to_unopenable_symlink_body()
{
	mkfile file1 1
	mkfile file2 2
	mksymlink file2 symlink1

	atf_check -s exit:0 -o empty -e empty chmod a-w symlink1
	atf_check -s exit:0 -o empty -e empty cp -f file1 symlink1
	atf_check -s exit:0 -o file:file1 -e empty cat symlink1
	atf_check -s exit:0 -o not-file:file1 -e empty cat file2
}

atf_test_case cp_RP_dangling_symlink_to_file_symlink
cp_RP_dangling_symlink_to_file_symlink_head()
{
	atf_set "descr" "cp -RP should copy to a dangling symlink."
}

cp_RP_dangling_symlink_to_file_symlink_body()
{
	mkfile file1 1
	mksymlink file1 symlink1
	mksymlink file2 symlink2

	atf_check -s exit:0 -o empty -e empty cp -a symlink1 symlink2
	atf_check -s exit:0 -o inline:"file1\n" -e empty readlink symlink1
	atf_check -s exit:0 -o inline:"file1\n" -e empty readlink symlink2
	atf_check -s exit:0 -o inline:"1\n" -e empty cat file1
}

atf_test_case cp_RP_dangling_symlink_to_dangling_symlink
cp_RP_dangling_symlink_to_dangling_symlink_head()
{
	atf_set "descr" "cp -RP should copy to a dangling symlink."
}

cp_RP_dangling_symlink_to_dangling_symlink_body()
{
	mksymlink file1 symlink1
	mksymlink file2 symlink2

	atf_check -s exit:0 -o empty -e empty cp -a symlink1 symlink2
	atf_check -s exit:0 -o inline:"file1\n" -e empty readlink symlink1
	atf_check -s exit:0 -o inline:"file1\n" -e empty readlink symlink2
}

atf_test_case cp_RP_dir_to_dir_symlink
cp_RP_dir_to_dir_symlink_head()
{
	atf_set "descr" "cp -RP should fail when copying a dir to a non-dir"
}

cp_RP_dir_to_dir_symlink_body()
{
	mkdirectory dir1
	mkdirectory dir2
	mksymlink ../dir3 dir2/dir1
	mkdirectory dir4

	atf_check -s not-exit:0 -o empty \
	    -e inline:"cp: dir2/dir1: Not a directory\n" cp -RP dir1 dir2
}

atf_init_test_cases()
{
	atf_add_test_case cp_file_self_symlink

	atf_add_test_case cp_f_file_to_file_symlink
	atf_add_test_case cp_f_file_to_dangling_symlink
	atf_add_test_case cp_f_file_to_unopenable_symlink

	atf_add_test_case cp_RP_dangling_symlink_to_file_symlink
	atf_add_test_case cp_RP_dangling_symlink_to_dangling_symlink
	atf_add_test_case cp_RP_dir_to_dir_symlink
}

# Helper subroutines.

mkdirectory()
{
	atf_check -s exit:0 -o empty -e empty mkdir "$1"
}

mkfile()
{
	atf_check -x -s exit:0 -o empty -e empty "echo $2 > \"$1\""
}

mksymlink()
{
	atf_check -s exit:0 -o empty -e empty ln -s "$1" "$2"
}
