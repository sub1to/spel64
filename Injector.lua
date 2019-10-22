project "Injector"
	uuid				"615c6539-4212-466f-8bfb-a567470695eb"
	kind				"ConsoleApp"
	characterset		"MBCS"

	files
	{
		"Injector/**.inc",
		"Injector/**.asm",
		"Injector/**.cpp",
		"Injector/**.h",
		"Injector/**.rc",
		
		"spel64/spel64.h",
	}	
	
	vpaths {
		["*"]			= { "Injector" },
		["spel64/*"]	= { "spel64" },
	}
	
	includedirs {
		"Injector/",
		"spel64/",
	}
	
	libdirs {
		"Injector/",
		"spel64/",
	}
	
	links {
		"spel64",
	}
		
	filter "configurations:Debug"
		defines { "DEBUG" }
		optimize "Off"
		symbols "On"
		
	filter "configurations:Dev"
		flags { "LinkTimeOptimization", "NoIncrementalLink" }
		optimize "Off"
		symbols "Off"
		
	filter "configurations:Release"
		flags { "LinkTimeOptimization", "NoIncrementalLink" }
		defines { "NDEBUG" }
		optimize "Full"
		symbols "Off"