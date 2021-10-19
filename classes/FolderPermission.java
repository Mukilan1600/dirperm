import java.sql.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.crypto.Data;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import permission.DirectoryPermissions;
import permission.PermissionEntry;
import permission.PermissionManager;

public class FolderPermission extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)throws IOException
    {
        int depth = Integer.parseInt(request.getParameter("depth"));
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter out = response.getWriter();

        List<String> directories =  DatabaseManager.getDirectoriesAtDepth(depth);
        List<DirectoryPermissions> directoryPermissions = DatabaseManager.getDirectoryPermissions(directories);
        out.print(new JSONArray(directoryPermissions));
        out.flush();
    }

    @Override
    public void doPost(HttpServletRequest request,HttpServletResponse response)throws IOException, ServletException
    {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter out = response.getWriter();
        StringBuilder reqStr = new StringBuilder();
        String line = null;
        BufferedReader reader = request.getReader();
        while((line=reader.readLine())!=null){
            reqStr.append(line);
        }
        try{
            JSONArray reqJson = new JSONArray(reqStr.toString());
            PermissionEntry grantEntry = new PermissionEntry(reqJson.getJSONObject(0)),
                                denyEntry =  new PermissionEntry(reqJson.getJSONObject(1));
            PermissionManager.setDirectoryPermissions(reqJson.getJSONObject(0).getString("fileName"),reqJson.getJSONObject(0).getString("userName"),grantEntry,denyEntry);
            out.write(reqJson.getJSONObject(0).getString("fileName"));
            out.flush();
        }catch(JSONException e){
            response.setStatus(400);
            out.println("{"+"\""+"err"+"\""+":\""+e.getMessage()+"\"}");
            out.flush();
        }
    }

}

