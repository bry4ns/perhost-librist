# librist. Copyright (c) 2020 SipRadius LLC. All right reserved.
# Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
# SPDX-License-Identifier: BSD-2-Clause

tools_dependencies = []
tools_deps = []
if host_machine.system() == 'windows'
	tools_deps += ['../contrib/getopt-shim.c']
	tools_dependencies += [ cc.find_library('ws2_32') ]
endif

tools_deps += [	'../contrib/time-shim.c']
tools_deps += [	'../contrib/pthread-shim.c']

if filter_obj
	tools_deps += [objcopy_fake_file ]
endif

srp_shared = []
if have_srp
	srp_shared += 'srp_shared.c'
	tools_dependencies += crypto_deps
endif

#On ubuntu cjson does not come with pkgconfig files, hence the extended checking.
if not builtin_cjson
	cjson_lib = dependency('libcjson', required: false)
	if not cjson_lib.found()
		cjson_lib = cc.find_library('cjson', required: required_library, has_headers: ['cjson/cJSON.h'])
		if not cjson_lib.found()
			builtin_cjson = true
		endif
	endif
endif
if builtin_cjson
	message('Using builtin cJSON library')
	cjson_lib = declare_dependency( compile_args : '-DCJSON_HIDE_SYMBOLS',
									sources: '../contrib/contrib_cJSON/cjson/cJSON.c',
									include_directories : include_directories('../contrib/contrib_cJSON'))
endif

if compile_prometheus
	prometheuslib = static_library('prometheus', 'prometheus-exporter.c', include_directories: [inc, '../contrib/contrib_cJSON'])
	prometheus_dep = declare_dependency(link_with: prometheuslib, include_directories: include_directories('.'), dependencies: [microhttpd, cjson_lib])
	tools_dependencies += prometheus_dep
endif

ristsender_exe = executable('ristsender',
	['ristsender.c', 'yamlparse.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	dependencies: [
		librist_dep,
		threads,
		stdatomic_dependency,
		tools_dependencies,
		cjson_lib,
	],
	include_directories: inc,
	install: should_install)

ristreceiver_exe = executable('ristreceiver',
	['ristreceiver.c', 'yamlparse.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	dependencies: [
		librist_dep,
		tools_dependencies,
		threads,
		cjson_lib,
	],

	include_directories: inc,
	install: should_install)

executable('rist2rist',
	['rist2rist.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	dependencies: [
		tools_dependencies,
		threads,
		librist_dep,
		cjson_lib,
	],
	include_directories: inc,
	install: should_install)

executable('udp2udp',
	['udp2udp.c', 'yamlparse.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	dependencies: [
		tools_dependencies,
		threads,
		librist_dep,
		cjson_lib,
	],
	include_directories: inc,
	install: should_install)

srt_lib = cc.find_library('srt', required: false, has_headers: ['srt/srt.h'])
if srt_lib.found()
 executable('perhost-rist',
 	['perhost-rist.c', srp_shared, tools_deps, rev_target],
 	dependencies: [librist_dep, srt_lib, tools_dependencies, threads],
 	include_directories: inc,
 	install: should_install)
endif

# risttunnel: IP tunnel over RIST (TUN support is now in librist)
if host_machine.system() == 'linux' or host_machine.system() == 'darwin' or host_machine.system() == 'windows'
	executable('risttunnel',
		['risttunnel.c', srp_shared, tools_deps, rev_target],
		dependencies: [
			librist_dep,
			tools_dependencies,
			threads,
		],
		include_directories: inc,
		install: should_install)
endif

if mbedcrypto_lib_found or use_nettle
	executable('ristsrppasswd',
			['ristsrppasswd.c', tools_deps],
			dependencies: [
				librist_dep,
				crypto_deps,
				threads,
			],
			include_directories: inc,
			install: should_install)
endif
