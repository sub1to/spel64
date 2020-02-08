project "spel64"
	uuid				"dd4c6a9b-694e-4b0e-8181-c994948af905"
	kind				"SharedLib"
	characterset		"MBCS"

	files
	{
		"spel64/**.inc",
		"spel64/**.asm",
		"spel64/**.cpp",
		"spel64/**.h",
		"spel64/**.rc",
	}	
	
	vpaths {
		["*"]	= { "spel64" },
	}
	
	includedirs {
		"spel64/",
	}
	
	libdirs {
		"spel64/",
	}
		
	filter "configurations:Debug*"
		defines { "DEBUG" }
		optimize "Off"
		symbols "On"
		
	filter "configurations:Dev*"
		flags { "LinkTimeOptimization", "NoIncrementalLink" }
		optimize "Off"
		symbols "Off"
		
	filter "configurations:Release*"
		flags { "LinkTimeOptimization", "NoIncrementalLink" }
		defines { "NDEBUG" }
		optimize "Full"
		symbols "Off"
