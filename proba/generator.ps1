Documentimo -FilePath "C:\Starter-AD.docx" {
    DocTOC -Title 'Table of content'

    DocPageBreak

    DocText {
        "Jest to dokumentacja domeny ActiveDirectory przeprowadzona w domena.local. Wszytskie informacje są tajne"
    }

    #OU
    DocNumbering -Text 'Spis jednostek organizacyjnych' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis jednostek organizacyjnych wraz z informacjami o każdej z nich"
        }
        #DocTable -DataTable $ADForest.ForestInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Forest Summary'
        DocText -LineBreak
    }
    
    #Grupy
    DocNumbering -Text 'Spis grup' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis grup w każdej jednostce organizacyjnej"
        }
        #DocTable -DataTable $ADForest.ForestInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Forest Summary'
        DocText -LineBreak
    }

    #Użytkownicy
    DocNumbering -Text 'Spis użytkowników' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis użytkowników w każdej jednostce organizacyjnej"
        }
        #DocTable -DataTable $ADForest.ForestInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Forest Summary'
        DocText -LineBreak
    }

    <#
    #Inna część
    DocNumbering -Text 'Spis użytkowników' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis użytkowników w każdej jednostce organizacyjnej"
        }
        #DocTable -DataTable $ADForest.ForestInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Forest Summary'
        DocText -LineBreak
    }
    #>

}
